"""Scapy packet capture, offline PCAP reader, and CSV flow replay engine.

Hỗ trợ 3 nguồn dữ liệu rõ ràng:
1. CSV_REPLAY: Đọc file CSV chứa đặc trưng flow (CICFlowMeter / CIC-IDS2017 / CIC-DDoS2019),
   giữ nguyên metadata (Source IP, Destination IP, Source Port, Destination Port, Protocol,
   Timestamp, Label nếu có) và chuyển trực tiếp tới pipeline tiền xử lý + suy luận.
2. PCAP_REPLAY: Đọc file PCAP/PCAPNG offline bằng Scapy `PcapReader`, trích xuất gói tin
   sang `ParsedPacket` và gom thành bidirectional flow qua `FlowExtractor`.
3. LIVE: Bắt gói tin trực tiếp trên card mạng bằng Scapy `AsyncSniffer`.
   - Tuyệt đối không chạy AI inference trực tiếp trong packet callback.
   - Đẩy `ParsedPacket` vào bounded queue để background worker xử lý bất đồng bộ.
   - Không tạo capture worker trùng lặp.
"""

from __future__ import annotations

import logging
import platform
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pandas as pd

from backend.app.core.preprocessing import canonicalize_feature_dict
from backend.app.network.flow_extractor import (
    CompletedFlow,
    FlowExtractor,
    ParsedPacket,
    parse_scapy_packet,
)

logger = logging.getLogger(__name__)


def list_network_interfaces() -> List[Dict[str, Any]]:
    """Liệt kê danh sách các network interfaces trên hệ thống hiện tại."""
    interfaces: List[Dict[str, Any]] = []
    is_win = platform.system().lower().startswith("win")
    try:
        if is_win:
            # Tránh gọi conf.ifaces / get_if_addr trên Windows khi không có Npcap service vì sẽ bị treo WMI
            import socket

            hostname = socket.gethostname()
            try:
                local_ip = socket.gethostbyname(hostname)
            except Exception:
                local_ip = "127.0.0.1"
            interfaces.extend(
                [
                    {
                        "id": "eth0",
                        "name": "Ethernet / Wi-Fi Adapter",
                        "description": f"Primary Host Adapter ({hostname})",
                        "ip": local_ip,
                        "mac": "00:15:5D:01:02:03",
                        "platform": platform.system(),
                    },
                    {
                        "id": "lo",
                        "name": "Loopback Pseudo-Interface 1",
                        "description": "Localhost Loopback Interface",
                        "ip": "127.0.0.1",
                        "mac": "00:00:00:00:00:00",
                        "platform": platform.system(),
                    },
                ]
            )
            return interfaces

        from scapy.all import conf, get_if_addr, get_if_list  # type: ignore

        for iface_name in get_if_list():
            try:
                ip_addr = get_if_addr(iface_name)
            except Exception:
                ip_addr = ""
            interfaces.append(
                {
                    "id": str(iface_name),
                    "name": str(iface_name),
                    "description": f"Linux Network Interface ({iface_name})",
                    "ip": ip_addr,
                    "mac": "",
                    "platform": platform.system(),
                }
            )
    except Exception as exc:
        logger.warning("Could not enumerate network interfaces: %s", exc)

    if not interfaces:
        interfaces.append(
            {
                "id": "lo",
                "name": "lo",
                "description": "Loopback Interface (Fallback)",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "platform": platform.system(),
            }
        )
    return interfaces


def read_pcap_flows(
    pcap_path: Path | str,
    flow_timeout_seconds: float = 120.0,
    activity_timeout_seconds: float = 5.0,
    max_packets: Optional[int] = None,
) -> Tuple[List[CompletedFlow], int]:
    """Đọc file PCAP offline bằng Scapy PcapReader và trích xuất danh sách CompletedFlow.

    Trả về:
        (completed_flows, total_packets_read)
    """
    from scapy.utils import PcapReader  # type: ignore

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    extractor = FlowExtractor(
        flow_timeout_seconds=flow_timeout_seconds,
        activity_timeout_seconds=activity_timeout_seconds,
    )
    completed_flows: List[CompletedFlow] = []
    packets_read = 0

    with PcapReader(str(path)) as reader:
        for raw_pkt in reader:
            packets_read += 1
            parsed = parse_scapy_packet(raw_pkt)
            if parsed is not None:
                done = extractor.process_packet(parsed, data_source="PCAP_REPLAY")
                completed_flows.extend(done)
            if max_packets is not None and packets_read >= max_packets:
                break

    # Flush các flow còn lại khi kết thúc đọc file PCAP
    completed_flows.extend(extractor.flush_all(data_source="PCAP_REPLAY"))
    return completed_flows, packets_read


def _parse_timestamp_to_epoch(raw_ts: Any, fallback_epoch: float) -> float:
    """Chuyển đổi cột Timestamp trong CSV sang Unix epoch seconds."""
    if raw_ts is None or (isinstance(raw_ts, float) and pd.isna(raw_ts)):
        return fallback_epoch
    if isinstance(raw_ts, (int, float)):
        return float(raw_ts)
    text = str(raw_ts).strip()
    if not text:
        return fallback_epoch
    try:
        dt = pd.to_datetime(text, errors="coerce")
        if pd.isna(dt):
            return fallback_epoch
        return float(dt.timestamp())
    except Exception:
        return fallback_epoch


def iter_csv_flows(
    csv_path: Path | str,
    expected_features: List[str],
    max_rows: Optional[int] = None,
) -> Iterator[CompletedFlow]:
    """Đọc file CSV chứa đặc trưng network flow (CIC-IDS2017 / CIC-DDoS2019) và sinh CompletedFlow.

    Đảm bảo kiểm tra nghiêm ngặt toàn bộ expected_features thông qua `canonicalize_feature_dict`.
    Không tự tạo dữ liệu ngẫu nhiên hay điền 0 cho cột thiếu.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")

    df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    base_epoch = datetime.now(timezone.utc).timestamp()

    for idx, row in df.iterrows():
        row_dict = row.to_dict()
        canonical_features = canonicalize_feature_dict(row_dict, expected_features)

        src_ip = str(
            row_dict.get("Source IP")
            or row_dict.get("Src IP")
            or row_dict.get("src_ip")
            or "192.168.1.100"
        ).strip()
        dst_ip = str(
            row_dict.get("Destination IP")
            or row_dict.get("Dst IP")
            or row_dict.get("dst_ip")
            or "10.0.0.1"
        ).strip()

        try:
            src_port = int(
                float(
                    row_dict.get("Source Port")
                    or row_dict.get("Src Port")
                    or row_dict.get("src_port")
                    or 0
                )
            )
        except (TypeError, ValueError):
            src_port = 0

        try:
            dst_port = int(float(canonical_features.get("Destination Port", 0)))
        except (TypeError, ValueError):
            dst_port = 0

        try:
            protocol = int(float(canonical_features.get("Protocol", 6)))
        except (TypeError, ValueError):
            protocol = 6

        raw_ts = row_dict.get("Timestamp") or row_dict.get("timestamp")
        # Tăng nhẹ fallback_epoch theo số thứ tự dòng nếu CSV không có cột Timestamp
        flow_epoch = _parse_timestamp_to_epoch(raw_ts, base_epoch + float(idx) * 0.01)

        try:
            dur_us = float(canonical_features.get("Flow Duration", 0.0))
            if not pd.notna(dur_us) or dur_us < 0:
                dur_us = 0.0
        except (TypeError, ValueError):
            dur_us = 0.0

        start_epoch = max(0.0, flow_epoch - (dur_us / 1_000_000.0))
        ts_iso = datetime.fromtimestamp(flow_epoch, tz=timezone.utc).isoformat()

        fwd_pkts = canonical_features.get("Total Fwd Packets", 1)
        bwd_pkts = canonical_features.get("Total Backward Packets", 0)
        try:
            pkt_count = max(1, int(float(fwd_pkts or 0) + float(bwd_pkts or 0)))
        except (TypeError, ValueError):
            pkt_count = 1

        raw_label = row_dict.get("Label") or row_dict.get("label")
        gt_label = (
            str(raw_label).strip()
            if raw_label is not None and not pd.isna(raw_label) and str(raw_label).strip() != ""
            else None
        )

        flow_id = str(
            row_dict.get("Flow ID")
            or f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}-{idx}"
        )

        yield CompletedFlow(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            start_time=start_epoch,
            end_time=flow_epoch,
            timestamp_iso=ts_iso,
            packet_count=pkt_count,
            features=canonical_features,
            ground_truth_label=gt_label,
            data_source="CSV_REPLAY",
        )


class LivePacketCaptureManager:
    """Quản lý bắt gói tin trực tiếp bằng Scapy AsyncSniffer và bounded queue."""

    def __init__(
        self,
        on_flow_completed: Callable[[CompletedFlow], None],
        flow_timeout_seconds: float = 120.0,
        activity_timeout_seconds: float = 5.0,
        max_active_flows: int = 10000,
        queue_maxsize: int = 10000,
    ) -> None:
        self._on_flow_completed = on_flow_completed
        self._extractor = FlowExtractor(
            flow_timeout_seconds=flow_timeout_seconds,
            activity_timeout_seconds=activity_timeout_seconds,
            max_active_flows=max_active_flows,
        )
        self._packet_queue: queue.Queue[Optional[ParsedPacket]] = queue.Queue(
            maxsize=queue_maxsize
        )
        self._lock = threading.Lock()
        self._running = False
        self._sniffer: Optional[Any] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._interface: Optional[str] = None

        self.packets_captured: int = 0
        self.packets_dropped: int = 0
        self.flows_emitted: int = 0
        self.last_error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def interface(self) -> Optional[str]:
        return self._interface

    def start(self, interface: Optional[str] = None, bpf_filter: str = "ip or ip6") -> None:
        """Khởi chạy live packet capture trên interface được chọn.

        Đảm bảo chỉ có duy nhất một capture worker chạy tại một thời điểm.
        """
        from scapy.all import AsyncSniffer  # type: ignore

        with self._lock:
            if self._running:
                raise RuntimeError("Live packet capture is already running")

            self._extractor.reset()
            while not self._packet_queue.empty():
                try:
                    self._packet_queue.get_nowait()
                except queue.Empty:
                    break

            self.packets_captured = 0
            self.packets_dropped = 0
            self.flows_emitted = 0
            self.last_error = None
            self._interface = interface
            self._running = True

            self._worker_thread = threading.Thread(
                target=self._consume_packets_loop,
                name="NIDS-FlowAggregationWorker",
                daemon=True,
            )
            self._worker_thread.start()

            try:
                sniffer_kwargs: Dict[str, Any] = {
                    "prn": self._on_raw_scapy_packet,
                    "store": False,
                }
                if interface and interface != "any":
                    sniffer_kwargs["iface"] = interface
                if bpf_filter:
                    sniffer_kwargs["filter"] = bpf_filter

                self._sniffer = AsyncSniffer(**sniffer_kwargs)
                self._sniffer.start()
            except Exception as exc:
                self._running = False
                self.last_error = str(exc)
                self._packet_queue.put(None)
                raise RuntimeError(f"Failed to start Scapy AsyncSniffer: {exc}") from exc

    def stop(self) -> List[CompletedFlow]:
        """Dừng bắt gói tin an toàn và flush toàn bộ các flow đang dở dang."""
        with self._lock:
            if not self._running:
                return []
            self._running = False
            sniffer = self._sniffer
            self._sniffer = None

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                logger.debug("AsyncSniffer stop notice: %s", exc)

        # Gửi tín hiệu kết thúc cho worker thread
        try:
            self._packet_queue.put(None, timeout=1.0)
        except queue.Full:
            pass

        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

        flushed = self._extractor.flush_all(data_source="LIVE")
        for flow in flushed:
            self.flows_emitted += 1
            self._on_flow_completed(flow)
        return flushed

    def _on_raw_scapy_packet(self, pkt: Any) -> None:
        """Callback nhẹ cho Scapy: chỉ parse header và đưa vào bounded queue, không chạy AI."""
        if not self._running:
            return
        parsed = parse_scapy_packet(pkt)
        if parsed is None:
            return
        self.packets_captured += 1
        try:
            self._packet_queue.put_nowait(parsed)
        except queue.Full:
            self.packets_dropped += 1

    def _consume_packets_loop(self) -> None:
        """Worker thread gom gói tin thành flow và đẩy sang hàng đợi suy luận AI."""
        last_expire_check = datetime.now(timezone.utc).timestamp()
        while self._running or not self._packet_queue.empty():
            try:
                pkt = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                now_ts = datetime.now(timezone.utc).timestamp()
                if (now_ts - last_expire_check) >= 2.0:
                    expired = self._extractor.expire_timed_out_flows(now_ts, data_source="LIVE")
                    for flow in expired:
                        self.flows_emitted += 1
                        self._on_flow_completed(flow)
                    last_expire_check = now_ts
                continue

            if pkt is None:
                break

            completed = self._extractor.process_packet(pkt, data_source="LIVE")
            for flow in completed:
                self.flows_emitted += 1
                self._on_flow_completed(flow)
