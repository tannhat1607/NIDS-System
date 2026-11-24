"""Background Monitoring Orchestrator and WebSocket Connection Manager.

Đảm bảo:
- Không chạy AI inference trực tiếp trong packet callback.
- Không block FastAPI event loop (sử dụng background thread + bounded queue cho replay và live capture).
- Không tạo capture/replay worker trùng lặp.
- Hỗ trợ graceful shutdown.
- Truyền cảnh báo và thống kê realtime tới tất cả WebSocket clients đang kết nối.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket

from backend.app.config import DATA_DIR, settings
from backend.app.core.detection_engine import DetectionEngine, DetectionRecord, detection_engine
from backend.app.core.model_registry import ModelRegistry, model_registry
from backend.app.database.repository import SQLiteRepository, db_repository
from backend.app.network.flow_extractor import CompletedFlow
from backend.app.network.packet_capture import (
    LivePacketCaptureManager,
    iter_csv_flows,
    read_pcap_flows,
)
from backend.app.network.sample_generator import ensure_sample_replay_files

logger = logging.getLogger(__name__)


class WebSocketHub:
    """Quản lý các kết nối WebSocket và phát thông điệp realtime không chặn luồng worker."""

    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        with self._lock:
            self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            self._clients.discard(ws)

    async def broadcast_json(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        stale: List[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        if stale:
            with self._lock:
                for ws in stale:
                    self._clients.discard(ws)

    def broadcast_from_thread(self, payload: Dict[str, Any]) -> None:
        """Gửi thông điệp tới các WebSocket clients từ một background worker thread."""
        with self._lock:
            has_clients = len(self._clients) > 0
        if not has_clients:
            return
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is loop:
            loop.create_task(self.broadcast_json(payload))
            return
        asyncio.run_coroutine_threadsafe(self.broadcast_json(payload), loop)


class MonitoringService:
    """Quản lý vòng đời phiên giám sát (LIVE, CSV_REPLAY, PCAP_REPLAY) và hàng đợi suy luận."""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        detector: Optional[DetectionEngine] = None,
        repository: Optional[SQLiteRepository] = None,
        ws_hub: Optional[WebSocketHub] = None,
    ) -> None:
        self.registry = registry or model_registry
        self.detector = detector or detection_engine
        self.repository = repository or db_repository
        self.ws_hub = ws_hub or WebSocketHub()

        self._lock = threading.Lock()
        self._is_monitoring: bool = False
        self._data_source: str = "IDLE"
        self._active_interface: Optional[str] = None
        self._active_file: Optional[str] = None
        self._started_at: Optional[str] = None
        self._last_error: Optional[str] = None

        self._flow_queue: queue.Queue[Optional[CompletedFlow]] = queue.Queue(
            maxsize=settings.inference_queue_maxsize
        )
        self._inference_thread: Optional[threading.Thread] = None
        self._producer_thread: Optional[threading.Thread] = None
        self._live_capture: Optional[LivePacketCaptureManager] = None

        self.packets_processed: int = 0
        self.flows_queued: int = 0
        self.flows_dropped: int = 0

    def get_status(self) -> Dict[str, Any]:
        runtime = self.detector.get_runtime_metrics()
        is_windows = platform.system().lower().startswith("win")
        live_validation_state = (
            "READY FOR LINUX VALIDATION" if is_windows else "LINUX_ENVIRONMENT_DETECTED"
        )
        return {
            "is_monitoring": self._is_monitoring,
            "data_source": self._data_source,
            "active_profile": self.registry.active_profile_id,
            "session_id": self.detector.current_session_id,
            "interface": self._active_interface,
            "file_path": self._active_file,
            "started_at": self._started_at,
            "last_error": self._last_error,
            "packets_processed": self.packets_processed,
            "flows_queued": self.flows_queued,
            "flows_dropped": self.flows_dropped,
            "live_validation_status": live_validation_state,
            **runtime,
        }

    def start_monitoring(
        self,
        profile_id: str,
        data_source: str,
        interface: Optional[str] = None,
        file_path: Optional[str] = None,
        replay_delay_ms: int = 60,
        max_rows: Optional[int] = 200,
    ) -> Dict[str, Any]:
        """Bắt đầu một phiên giám sát mới. Đảm bảo không tạo worker trùng lặp."""
        source_upper = data_source.strip().upper()
        if source_upper not in ("LIVE", "CSV_REPLAY", "PCAP_REPLAY"):
            raise ValueError(f"Unsupported data_source: {data_source}")

        with self._lock:
            if self._is_monitoring:
                raise RuntimeError("A monitoring session is already running. Stop it first.")

            # Chuyển profile và khởi tạo session mới
            profile = self.registry.set_active_profile(profile_id)
            session_id = self.detector.start_new_session(
                profile_id=profile.profile_id, reset_analytics=False
            )

            # Xóa hàng đợi flow cũ
            while not self._flow_queue.empty():
                try:
                    self._flow_queue.get_nowait()
                except queue.Empty:
                    break

            self.packets_processed = 0
            self.flows_queued = 0
            self.flows_dropped = 0
            self._last_error = None
            self._data_source = source_upper
            self._active_interface = interface
            self._started_at = datetime.now(timezone.utc).isoformat()

            sample_paths = ensure_sample_replay_files()
            resolved_file: Optional[Path] = None

            if source_upper == "CSV_REPLAY":
                if file_path and file_path.strip():
                    resolved_file = Path(file_path.strip())
                else:
                    resolved_file = Path(
                        sample_paths["cic_ids2017_csv"]
                        if profile.profile_id == "CIC-IDS2017"
                        else sample_paths["cic_ddos2019_csv"]
                    )
                if not resolved_file.exists():
                    raise FileNotFoundError(f"CSV replay file not found: {resolved_file}")
                self._active_file = str(resolved_file)

            elif source_upper == "PCAP_REPLAY":
                if file_path and file_path.strip():
                    resolved_file = Path(file_path.strip())
                else:
                    resolved_file = Path(sample_paths["sample_pcap"])
                if not resolved_file.exists():
                    raise FileNotFoundError(f"PCAP replay file not found: {resolved_file}")
                self._active_file = str(resolved_file)
            else:
                self._active_file = None

            self._is_monitoring = True

            self.repository.create_session(
                session_id=session_id,
                profile_id=profile.profile_id,
                data_source=source_upper,
                interface_or_file=interface or (str(resolved_file) if resolved_file else ""),
            )
            self.repository.log_event(
                event_type="MONITORING_START",
                message=(
                    f"Started {source_upper} monitoring with profile {profile.profile_id}"
                ),
                severity="INFO",
                session_id=session_id,
            )

            # Khởi động luồng tiêu thụ flow & chạy CNN-LSTM inference
            self._inference_thread = threading.Thread(
                target=self._inference_consumer_loop,
                args=(session_id, profile.profile_id),
                name="NIDS-InferenceWorker",
                daemon=True,
            )
            self._inference_thread.start()

            if source_upper == "LIVE":
                self._live_capture = LivePacketCaptureManager(
                    on_flow_completed=self._enqueue_completed_flow,
                    flow_timeout_seconds=settings.flow_timeout_seconds,
                    activity_timeout_seconds=settings.activity_timeout_seconds,
                    max_active_flows=settings.max_active_flows,
                )
                try:
                    self._live_capture.start(interface=interface)
                except Exception as exc:
                    self._is_monitoring = False
                    self._last_error = str(exc)
                    self._flow_queue.put(None)
                    self.repository.finalize_session(
                        session_id=session_id,
                        total_packets=0,
                        total_flows=0,
                        total_inferences=0,
                        total_alerts=0,
                        status="FAILED",
                    )
                    raise
            elif source_upper == "CSV_REPLAY":
                assert resolved_file is not None
                self._producer_thread = threading.Thread(
                    target=self._csv_replay_producer_loop,
                    args=(resolved_file, profile.feature_names, replay_delay_ms, max_rows),
                    name="NIDS-CSVReplayWorker",
                    daemon=True,
                )
                self._producer_thread.start()
            elif source_upper == "PCAP_REPLAY":
                assert resolved_file is not None
                self._producer_thread = threading.Thread(
                    target=self._pcap_replay_producer_loop,
                    args=(resolved_file, replay_delay_ms, max_rows),
                    name="NIDS-PCAPReplayWorker",
                    daemon=True,
                )
                self._producer_thread.start()

        status = self.get_status()
        self.ws_hub.broadcast_from_thread({"type": "STATUS_UPDATE", "data": status})
        return status

    def stop_monitoring(self) -> Dict[str, Any]:
        """Dừng phiên giám sát hiện tại một cách an toàn (graceful shutdown)."""
        with self._lock:
            if not self._is_monitoring:
                return self.get_status()
            self._is_monitoring = False
            live_cap = self._live_capture
            self._live_capture = None
            session_id = self.detector.current_session_id

        if live_cap is not None:
            try:
                live_cap.stop()
                self.packets_processed = live_cap.packets_captured
            except Exception as exc:
                logger.warning("Error stopping live capture: %s", exc)

        if self._producer_thread is not None and self._producer_thread.is_alive():
            self._producer_thread.join(timeout=3.0)

        try:
            self._flow_queue.put(None, timeout=1.0)
        except queue.Full:
            pass

        if self._inference_thread is not None and self._inference_thread.is_alive():
            self._inference_thread.join(timeout=5.0)

        # Lưu ứng viên Beaconing vào SQLite và đóng session
        candidates = self.detector.get_beaconing_candidates(only_suspected=False)
        self.repository.upsert_beaconing_candidates(candidates)

        metrics = self.detector.get_runtime_metrics()
        self.repository.finalize_session(
            session_id=session_id,
            total_packets=self.packets_processed,
            total_flows=metrics["total_flows_seen"],
            total_inferences=metrics["total_inferences"],
            total_alerts=metrics["total_attacks"],
            status="STOPPED",
        )
        self.repository.log_event(
            event_type="MONITORING_STOP",
            message=f"Stopped monitoring session {session_id}",
            severity="INFO",
            session_id=session_id,
        )

        status = self.get_status()
        self.ws_hub.broadcast_from_thread({"type": "STATUS_UPDATE", "data": status})
        return status

    def run_synchronous_replay_file(
        self,
        file_path: Path,
        data_source: str,
        profile_id: Optional[str] = None,
        max_rows: Optional[int] = 200,
    ) -> Dict[str, Any]:
        """Xử lý trực tiếp một file CSV hoặc PCAP được upload hoặc chỉ định qua REST API."""
        profile = self.registry.get_profile(profile_id)
        session_id = self.detector.start_new_session(
            profile_id=profile.profile_id, reset_analytics=False
        )
        self.repository.create_session(
            session_id=session_id,
            profile_id=profile.profile_id,
            data_source=data_source,
            interface_or_file=str(file_path.name),
        )

        records: List[Dict[str, Any]] = []
        packets_count = 0

        if data_source == "CSV_REPLAY":
            flows = list(
                iter_csv_flows(file_path, expected_features=profile.feature_names, max_rows=max_rows)
            )
            packets_count = sum(f.packet_count for f in flows)
        elif data_source == "PCAP_REPLAY":
            flows, packets_count = read_pcap_flows(file_path, max_packets=max_rows)
        else:
            raise ValueError(f"Unsupported replay source: {data_source}")

        attack_count = 0
        benign_count = 0
        buffering_count = 0

        for flow in flows:
            rec = self.detector.process_flow(
                flow, profile_id=profile.profile_id, session_id=session_id
            )
            self.repository.insert_detection(rec)
            rec_dict = rec.to_dict()
            records.append(rec_dict)

            if rec.detection_status == "ATTACK":
                attack_count += 1
            elif rec.detection_status == "BENIGN":
                benign_count += 1
            else:
                buffering_count += 1

            self.ws_hub.broadcast_from_thread({"type": "DETECTION_EVENT", "data": rec_dict})

        candidates = self.detector.get_beaconing_candidates(only_suspected=False)
        self.repository.upsert_beaconing_candidates(candidates)
        self.repository.finalize_session(
            session_id=session_id,
            total_packets=packets_count,
            total_flows=len(flows),
            total_inferences=attack_count + benign_count,
            total_alerts=attack_count,
            status="COMPLETED",
        )
        self.ws_hub.broadcast_from_thread({"type": "STATUS_UPDATE", "data": self.get_status()})

        return {
            "session_id": session_id,
            "profile_id": profile.profile_id,
            "data_source": data_source,
            "file_name": file_path.name,
            "packets_processed": packets_count,
            "flows_processed": len(flows),
            "inferences_completed": attack_count + benign_count,
            "attack_count": attack_count,
            "benign_count": benign_count,
            "buffering_count": buffering_count,
            "records": records[:100],
        }

    def _enqueue_completed_flow(self, flow: CompletedFlow) -> None:
        if not self._is_monitoring:
            return
        self.flows_queued += 1
        if self._live_capture is not None:
            self.packets_processed = self._live_capture.packets_captured
        try:
            self._flow_queue.put_nowait(flow)
        except queue.Full:
            self.flows_dropped += 1

    def _csv_replay_producer_loop(
        self,
        csv_path: Path,
        expected_features: List[str],
        replay_delay_ms: int,
        max_rows: Optional[int],
    ) -> None:
        try:
            for flow in iter_csv_flows(csv_path, expected_features, max_rows=max_rows):
                if not self._is_monitoring:
                    break
                self.packets_processed += flow.packet_count
                self._enqueue_completed_flow(flow)
                if replay_delay_ms > 0:
                    time.sleep(replay_delay_ms / 1000.0)
        except Exception as exc:
            logger.error("CSV replay error: %s", exc)
            self._last_error = str(exc)
        finally:
            self._flow_queue.put(None)

    def _pcap_replay_producer_loop(
        self,
        pcap_path: Path,
        replay_delay_ms: int,
        max_packets: Optional[int],
    ) -> None:
        try:
            flows, pkts = read_pcap_flows(pcap_path, max_packets=max_packets)
            self.packets_processed = pkts
            for flow in flows:
                if not self._is_monitoring:
                    break
                self._enqueue_completed_flow(flow)
                if replay_delay_ms > 0:
                    time.sleep(replay_delay_ms / 1000.0)
        except Exception as exc:
            logger.error("PCAP replay error: %s", exc)
            self._last_error = str(exc)
        finally:
            self._flow_queue.put(None)

    def _inference_consumer_loop(self, session_id: str, profile_id: str) -> None:
        try:
            while self._is_monitoring or not self._flow_queue.empty():
                try:
                    flow = self._flow_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                if flow is None:
                    break

                rec: DetectionRecord = self.detector.process_flow(
                    flow, profile_id=profile_id, session_id=session_id
                )
                self.repository.insert_detection(rec)
                rec_dict = rec.to_dict()
                self.ws_hub.broadcast_from_thread(
                    {
                        "type": "DETECTION_EVENT",
                        "data": rec_dict,
                        "status": self.get_status(),
                    }
                )
        except Exception as exc:
            logger.error("Inference consumer error: %s", exc)
            self._last_error = str(exc)
        finally:
            with self._lock:
                self._is_monitoring = False
            candidates = self.detector.get_beaconing_candidates(only_suspected=False)
            self.repository.upsert_beaconing_candidates(candidates)
            metrics = self.detector.get_runtime_metrics()
            self.repository.finalize_session(
                session_id=session_id,
                total_packets=self.packets_processed,
                total_flows=metrics["total_flows_seen"],
                total_inferences=metrics["total_inferences"],
                total_alerts=metrics["total_attacks"],
                status="COMPLETED" if not self._last_error else "FAILED",
            )
            self.ws_hub.broadcast_from_thread(
                {"type": "STATUS_UPDATE", "data": self.get_status()}
            )


ws_hub = WebSocketHub()
monitoring_service = MonitoringService(ws_hub=ws_hub)
