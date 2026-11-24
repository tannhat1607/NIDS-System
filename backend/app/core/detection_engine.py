"""Unified Detection Engine orchestrating CNN-LSTM inference, Temporal Window, Gaussian, Beaconing, and Graph Analysis.

Nguyên tắc thiết kế:
- CNN-LSTM là mô hình chính thức duy nhất quyết định `BENIGN` hoặc `ATTACK` theo quy tắc argmax.
- Với profile `CIC-IDS2017`: suy luận ngay trên từng flow đã hoàn thành (`window_size = 1`).
- Với profile `CIC-DDoS2019`: gom flow theo Source IP vào `TemporalWindowBuffer` (`window_size = 8`, `stride = 8`,
  `0 < duration <= 300s`). Nếu chưa đủ 8 flows hợp lệ, trả kết quả `detection_status = "BUFFERING"`.
  Khi đủ 8 flows, chạy Temporal CNN-LSTM và gắn kết quả với flow cuối cùng của cửa sổ.
- Gaussian Anomaly Detection chỉ gắn `gaussian_anomaly_score` và `gaussian_is_anomalous` bổ trợ,
  tuyệt đối không phủ quyết CNN-LSTM hay tự tạo cảnh báo ATTACK.
- Beaconing Detection và NetworkX Graph Analysis cập nhật thống kê bổ trợ theo thời gian thực.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import numpy as np

from backend.app.analysis.beaconing import BeaconingCandidate, BeaconingDetector
from backend.app.analysis.graph_analysis import GraphSummary, NetworkGraphAnalyzer
from backend.app.config import settings
from backend.app.core.inference import InferenceEngine, inference_engine
from backend.app.core.model_registry import ModelRegistry, model_registry
from backend.app.network.flow_extractor import CompletedFlow
from backend.app.network.temporal_window import TemporalWindowBuffer


@dataclass
class DetectionRecord:
    """Bản ghi kết quả phát hiện đầy đủ cho mỗi flow hoặc cửa sổ flow."""

    alert_id: str
    detected_at: str
    flow_timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    detection_status: str  # "BENIGN", "ATTACK", hoặc "BUFFERING"
    predicted_attack_type: str
    class_score: float
    attack_score: float
    gaussian_anomaly_score: float
    gaussian_threshold: float
    gaussian_is_anomalous: bool
    inference_latency_ms: float
    dataset_profile: str
    monitoring_session: str
    data_source: str  # "LIVE", "PCAP_REPLAY", "CSV_REPLAY"
    buffered_flows: int = 1
    required_window_size: int = 1
    ground_truth_label: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DetectionEngine:
    """Bộ điều phối trung tâm của NIDS kết nối Flow, Temporal Window, CNN-LSTM và Analytics."""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        engine: Optional[InferenceEngine] = None,
        on_detection: Optional[Callable[[DetectionRecord], None]] = None,
    ) -> None:
        self.registry = registry or model_registry
        self.engine = engine or inference_engine
        self.on_detection = on_detection

        self._lock = threading.Lock()
        self._current_session_id: str = f"session-{uuid.uuid4().hex[:8]}"

        self.temporal_buffer = TemporalWindowBuffer(
            window_size=8,
            stride=8,
            max_window_seconds=300.0,
            session_id=self._current_session_id,
        )
        self.beaconing_detector = BeaconingDetector(
            min_connections=settings.beaconing_min_connections,
            cov_threshold=settings.beaconing_cov_threshold,
        )
        self.graph_analyzer = NetworkGraphAnalyzer(
            max_nodes=settings.max_graph_nodes,
            retention_seconds=settings.graph_retention_seconds,
        )

        # Thống kê tích lũy
        self.total_flows_seen: int = 0
        self.total_inferences: int = 0
        self.total_attacks: int = 0
        self.total_benign: int = 0
        self.total_buffering: int = 0
        self.total_gaussian_anomalies: int = 0
        self._latencies_ms: List[float] = []
        self._recent_records: List[DetectionRecord] = []

    @property
    def current_session_id(self) -> str:
        return self._current_session_id

    def start_new_session(
        self,
        profile_id: Optional[str] = None,
        session_id: Optional[str] = None,
        reset_analytics: bool = False,
    ) -> str:
        """Khởi tạo một monitoring session mới và xóa temporal buffer cũ để không trộn flow."""
        with self._lock:
            if profile_id is not None:
                self.registry.set_active_profile(profile_id)
            self._current_session_id = session_id or f"session-{uuid.uuid4().hex[:8]}"
            self.temporal_buffer.reset(new_session_id=self._current_session_id)
            if reset_analytics:
                self.beaconing_detector.reset()
                self.graph_analyzer.reset()
                self.total_flows_seen = 0
                self.total_inferences = 0
                self.total_attacks = 0
                self.total_benign = 0
                self.total_buffering = 0
                self.total_gaussian_anomalies = 0
                self._latencies_ms.clear()
                self._recent_records.clear()
            return self._current_session_id

    def process_flow(
        self,
        flow: CompletedFlow,
        profile_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> DetectionRecord:
        """Xử lý một CompletedFlow qua profile đang chọn (CIC-IDS2017 hoặc CIC-DDoS2019)."""
        active_profile = self.registry.get_profile(profile_id)
        active_session = session_id or self._current_session_id
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            self.total_flows_seen += 1
            # Ghi nhận kết nối cho bộ phân tích Beaconing
            self.beaconing_detector.record_connection(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                timestamp=flow.end_time,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                session_id=active_session,
            )

        if active_profile.window_size == 1:
            # Profile CIC-IDS2017: Suy luận trực tiếp trên từng flow
            pred = self.engine.predict_single_flow(
                flow.features, profile_id=active_profile.profile_id
            )
            record = DetectionRecord(
                alert_id=f"det-{uuid.uuid4().hex[:12]}",
                detected_at=now_iso,
                flow_timestamp=flow.timestamp_iso,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                detection_status=pred.detection_status,
                predicted_attack_type=pred.predicted_label,
                class_score=round(pred.class_score, 6),
                attack_score=round(pred.attack_score, 6),
                gaussian_anomaly_score=round(pred.gaussian_anomaly_score, 4),
                gaussian_threshold=round(pred.gaussian_threshold, 4),
                gaussian_is_anomalous=pred.gaussian_is_anomalous,
                inference_latency_ms=round(pred.latency_ms, 4),
                dataset_profile=active_profile.profile_id,
                monitoring_session=active_session,
                data_source=flow.data_source,
                buffered_flows=1,
                required_window_size=1,
                ground_truth_label=flow.ground_truth_label,
            )
            self._commit_inference_stats(flow, record)
            return record

        # Profile CIC-DDoS2019: Đưa vào TemporalWindowBuffer (window_size=8, stride=8)
        with self._lock:
            if self.temporal_buffer.session_id != active_session:
                self.temporal_buffer.reset(new_session_id=active_session)
            win_res = self.temporal_buffer.add_flow(flow)

        if win_res.status != "READY" or not win_res.window_flows:
            with self._lock:
                self.total_buffering += 1
                self.graph_analyzer.record_flow(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    timestamp=flow.end_time,
                    is_attack=False,
                    attack_label="BUFFERING",
                    gaussian_anomaly_score=0.0,
                )
            buf_record = DetectionRecord(
                alert_id=f"buf-{uuid.uuid4().hex[:12]}",
                detected_at=now_iso,
                flow_timestamp=flow.timestamp_iso,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                detection_status="BUFFERING",
                predicted_attack_type="BUFFERING",
                class_score=0.0,
                attack_score=0.0,
                gaussian_anomaly_score=0.0,
                gaussian_threshold=round(active_profile.gaussian_threshold, 4),
                gaussian_is_anomalous=False,
                inference_latency_ms=0.0,
                dataset_profile=active_profile.profile_id,
                monitoring_session=active_session,
                data_source=flow.data_source,
                buffered_flows=win_res.buffered_count,
                required_window_size=win_res.required_window_size,
                ground_truth_label=flow.ground_truth_label,
                note=win_res.reason,
            )
            self._remember_record(buf_record)
            if self.on_detection is not None:
                self.on_detection(buf_record)
            return buf_record

        # Đã đủ 8 flows hợp lệ -> chạy Temporal CNN-LSTM
        window_flows = win_res.window_flows
        last_flow = window_flows[-1]
        pred = self.engine.predict_temporal_window(
            [f.features for f in window_flows], profile_id=active_profile.profile_id
        )
        record = DetectionRecord(
            alert_id=f"det-{uuid.uuid4().hex[:12]}",
            detected_at=now_iso,
            flow_timestamp=last_flow.timestamp_iso,
            source_ip=last_flow.src_ip,
            destination_ip=last_flow.dst_ip,
            source_port=last_flow.src_port,
            destination_port=last_flow.dst_port,
            protocol=last_flow.protocol,
            detection_status=pred.detection_status,
            predicted_attack_type=pred.predicted_label,
            class_score=round(pred.class_score, 6),
            attack_score=round(pred.attack_score, 6),
            gaussian_anomaly_score=round(pred.gaussian_anomaly_score, 4),
            gaussian_threshold=round(pred.gaussian_threshold, 4),
            gaussian_is_anomalous=pred.gaussian_is_anomalous,
            inference_latency_ms=round(pred.latency_ms, 4),
            dataset_profile=active_profile.profile_id,
            monitoring_session=active_session,
            data_source=last_flow.data_source,
            buffered_flows=8,
            required_window_size=8,
            ground_truth_label=last_flow.ground_truth_label,
            note=f"Temporal window 8 flows ({win_res.window_span_seconds:.2f}s)",
        )
        self._commit_inference_stats(last_flow, record)
        return record

    def get_beaconing_candidates(self, only_suspected: bool = False) -> List[BeaconingCandidate]:
        with self._lock:
            return self.beaconing_detector.get_candidates(only_suspected=only_suspected)

    def get_graph_summary(self) -> GraphSummary:
        with self._lock:
            return self.graph_analyzer.analyze()

    def get_recent_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._recent_records[-limit:][::-1]]

    def get_runtime_metrics(self) -> Dict[str, Any]:
        with self._lock:
            lat_arr = np.asarray(self._latencies_ms, dtype=np.float64) if self._latencies_ms else None
            avg_lat = float(np.mean(lat_arr)) if lat_arr is not None else 0.0
            p50_lat = float(np.percentile(lat_arr, 50)) if lat_arr is not None else 0.0
            p95_lat = float(np.percentile(lat_arr, 95)) if lat_arr is not None else 0.0

            return {
                "active_profile": self.registry.active_profile_id,
                "current_session_id": self._current_session_id,
                "total_flows_seen": self.total_flows_seen,
                "total_inferences": self.total_inferences,
                "total_attacks": self.total_attacks,
                "total_benign": self.total_benign,
                "total_buffering": self.total_buffering,
                "total_gaussian_anomalies": self.total_gaussian_anomalies,
                "inference_coverage_ratio": round(
                    self.total_inferences / max(1, self.total_flows_seen), 4
                ),
                "latency_avg_ms": round(avg_lat, 4),
                "latency_p50_ms": round(p50_lat, 4),
                "latency_p95_ms": round(p95_lat, 4),
                "buffered_ips": self.temporal_buffer.get_all_buffer_counts(),
            }

    def _commit_inference_stats(self, flow: CompletedFlow, record: DetectionRecord) -> None:
        with self._lock:
            self.total_inferences += 1
            if record.detection_status == "ATTACK":
                self.total_attacks += 1
            else:
                self.total_benign += 1
            if record.gaussian_is_anomalous:
                self.total_gaussian_anomalies += 1

            self._latencies_ms.append(record.inference_latency_ms)
            if len(self._latencies_ms) > 5000:
                del self._latencies_ms[: len(self._latencies_ms) - 5000]

            self.graph_analyzer.record_flow(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                timestamp=flow.end_time,
                is_attack=(record.detection_status == "ATTACK"),
                attack_label=record.predicted_attack_type,
                gaussian_anomaly_score=record.gaussian_anomaly_score,
            )

        self._remember_record(record)
        if self.on_detection is not None:
            self.on_detection(record)

    def _remember_record(self, record: DetectionRecord) -> None:
        with self._lock:
            self._recent_records.append(record)
            if len(self._recent_records) > 500:
                del self._recent_records[: len(self._recent_records) - 500]


# Singleton detection engine
detection_engine = DetectionEngine()
