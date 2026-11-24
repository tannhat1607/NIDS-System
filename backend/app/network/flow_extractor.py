"""CICFlowMeter-compatible bidirectional flow aggregator and 70-feature extractor.

Thực hiện trích xuất chính xác toàn bộ 70 đặc trưng của CIC-IDS2017 và 66 đặc trưng của
CIC-DDoS2019 (vốn là tập con của 70 đặc trưng, chỉ lược bỏ 4 cờ FIN/PSH/ECE/Fwd URG).

Đơn vị đo và công thức tuân thủ tuyệt đối chuẩn CICFlowMeter (ISCXFlowMeter):
- Thời gian (Flow Duration, IAT, Active, Idle): micro-giây (µs, 1 giây = 1,000,000 µs).
- Tốc độ (Flow Bytes/s, Flow Packets/s, Fwd Packets/s, Bwd Packets/s): tính theo giây (s).
- Kích thước gói tin (Packet Length, Total Length, Segment Size): tính theo byte của phần
  payload tầng Transport (TCP/UDP payload length) hoặc IP payload đối với giao thức khác,
  khớp với `PacketInfo.getPayloadBytes()` trong CICFlowMeter.
- Độ dài Header (Fwd/Bwd Header Length): tổng số byte của Transport Header (TCP dataofs * 4,
  UDP = 8 bytes).
- Cờ TCP (FIN, SYN, RST, PSH, ACK, URG, CWE/CWR, ECE): đếm số gói có bật bit cờ tương ứng.
- Active / Idle: ngưỡng tách hoạt động (activity timeout) mặc định = 5,000,000 µs (5 giây).
- Subflow: ngưỡng tách subflow mặc định = 1,000,000 µs (1 giây) theo chuẩn CICFlowMeter.
- Initial TCP Window Bytes: giá trị trường TCP window của gói đầu tiên ở chiều Forward / Backward
  (nếu không có gói TCP ở chiều đó, giá trị mặc định của CICFlowMeter là -1; tuy nhiên trong
  tập dữ liệu đã huấn luyện trên Colab, giá trị là số nguyên >= -1).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np


@dataclass
class ParsedPacket:
    """Thông tin gói tin tối giản được trích xuất từ Scapy Packet (không lưu raw payload)."""

    timestamp: float  # Unix epoch seconds (float)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP, ...
    payload_bytes: int  # Transport payload bytes
    header_bytes: int  # Transport header length in bytes
    tcp_window: int = -1
    flag_fin: int = 0
    flag_syn: int = 0
    flag_rst: int = 0
    flag_psh: int = 0
    flag_ack: int = 0
    flag_urg: int = 0
    flag_cwe: int = 0  # CWR / CWE bit (0x80)
    flag_ece: int = 0  # ECE bit (0x40)


@dataclass
class CompletedFlow:
    """Một network flow đã hoàn thành kèm metadata và dictionary 70 đặc trưng."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float
    end_time: float
    timestamp_iso: str
    packet_count: int
    features: Dict[str, float]
    ground_truth_label: Optional[str] = None
    data_source: str = "LIVE"


def parse_scapy_packet(pkt: Any, fallback_ts: Optional[float] = None) -> Optional[ParsedPacket]:
    """Chuyển đổi gói tin Scapy sang ParsedPacket chuẩn hóa.

    Không lưu trữ raw payload để đảm bảo an toàn bộ nhớ và quyền riêng tư.
    """
    try:
        # Hỗ trợ cả IPv4 và IPv6 nếu có
        if pkt.haslayer("IP"):
            ip_layer = pkt["IP"]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto = int(ip_layer.proto)
        elif pkt.haslayer("IPv6"):
            ip_layer = pkt["IPv6"]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto = int(ip_layer.nh)
        else:
            return None

        ts = float(pkt.time) if getattr(pkt, "time", None) is not None else (
            fallback_ts if fallback_ts is not None else datetime.now(timezone.utc).timestamp()
        )

        src_port = 0
        dst_port = 0
        header_bytes = 0
        payload_bytes = 0
        tcp_win = -1
        fin = syn = rst = psh = ack = urg = cwe = ece = 0

        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            proto = 6
            dataofs = getattr(tcp, "dataofs", None)
            header_bytes = int(dataofs * 4) if dataofs else 20
            payload_bytes = len(bytes(tcp.payload)) if tcp.payload else 0
            tcp_win = int(getattr(tcp, "window", 0))

            flags_int = int(tcp.flags)
            fin = 1 if (flags_int & 0x01) else 0
            syn = 1 if (flags_int & 0x02) else 0
            rst = 1 if (flags_int & 0x04) else 0
            psh = 1 if (flags_int & 0x08) else 0
            ack = 1 if (flags_int & 0x10) else 0
            urg = 1 if (flags_int & 0x20) else 0
            ece = 1 if (flags_int & 0x40) else 0
            cwe = 1 if (flags_int & 0x80) else 0
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            proto = 17
            header_bytes = 8
            payload_bytes = len(bytes(udp.payload)) if udp.payload else 0
        else:
            header_bytes = 8
            payload_bytes = len(bytes(ip_layer.payload)) if ip_layer.payload else 0

        return ParsedPacket(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            payload_bytes=max(0, payload_bytes),
            header_bytes=max(0, header_bytes),
            tcp_window=tcp_win,
            flag_fin=fin,
            flag_syn=syn,
            flag_rst=rst,
            flag_psh=psh,
            flag_ack=ack,
            flag_urg=urg,
            flag_cwe=cwe,
            flag_ece=ece,
        )
    except Exception:
        return None


def _safe_stats(values: List[float]) -> Tuple[float, float, float, float, float]:
    """Trả về (min, max, mean, std, variance) của danh sách số theo chuẩn sample std (ddof=1 khi n>1)."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    if n == 1:
        v = float(values[0])
        return v, v, v, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    vmin = float(np.min(arr))
    vmax = float(np.max(arr))
    vmean = float(np.mean(arr))
    vvar = float(np.var(arr, ddof=1))
    vstd = float(math.sqrt(max(0.0, vvar)))
    return vmin, vmax, vmean, vstd, vvar


@dataclass
class ActiveFlowState:
    """Trạng thái tích lũy của một bidirectional flow đang hoạt động."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_ts: float
    last_ts: float

    all_ts: List[float] = field(default_factory=list)
    fwd_ts: List[float] = field(default_factory=list)
    bwd_ts: List[float] = field(default_factory=list)

    all_lens: List[float] = field(default_factory=list)
    fwd_lens: List[float] = field(default_factory=list)
    bwd_lens: List[float] = field(default_factory=list)

    fwd_header_bytes: int = 0
    bwd_header_bytes: int = 0
    min_seg_size_forward: Optional[int] = None
    act_data_pkt_fwd: int = 0

    init_win_bytes_fwd: int = -1
    init_win_bytes_bwd: int = -1

    fwd_psh_flags: int = 0
    fwd_urg_flags: int = 0

    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    # Quản lý Active / Idle periods (theo micro-giây)
    start_active_ts: float = 0.0
    end_active_ts: float = 0.0
    active_durations_us: List[float] = field(default_factory=list)
    idle_durations_us: List[float] = field(default_factory=list)

    # Quản lý Subflow count
    subflow_count: int = 1
    last_subflow_ts: float = 0.0

    def add_packet(
        self,
        pkt: ParsedPacket,
        activity_timeout_s: float = 5.0,
        subflow_timeout_s: float = 1.0,
    ) -> None:
        """Cập nhật thống kê flow khi nhận một gói tin mới."""
        ts = pkt.timestamp
        is_forward = (
            pkt.src_ip == self.src_ip
            and pkt.src_port == self.src_port
            and pkt.dst_ip == self.dst_ip
            and pkt.dst_port == self.dst_port
        )

        if not self.all_ts:
            # Gói đầu tiên của flow
            self.start_ts = ts
            self.last_ts = ts
            self.start_active_ts = ts
            self.end_active_ts = ts
            self.last_subflow_ts = ts
            # CICFlowMeter ghi nhận gói đầu tiên vào cả danh sách độ dài gói chung để tính Min/Max/Mean/Std/Average Packet Size
            self.all_lens.append(float(pkt.payload_bytes))
        else:
            # Kiểm tra Subflow timeout (mặc định 1.0 giây trong CICFlowMeter)
            if (ts - self.last_subflow_ts) > subflow_timeout_s:
                self.subflow_count += 1
            self.last_subflow_ts = ts

            # Kiểm tra Active / Idle timeout (mặc định 5.0 giây trong CICFlowMeter)
            gap_s = ts - self.end_active_ts
            if gap_s > activity_timeout_s:
                active_dur_us = (self.end_active_ts - self.start_active_ts) * 1_000_000.0
                if active_dur_us > 0:
                    self.active_durations_us.append(active_dur_us)
                self.idle_durations_us.append(gap_s * 1_000_000.0)
                self.start_active_ts = ts
                self.end_active_ts = ts
            else:
                self.end_active_ts = ts

            if ts > self.last_ts:
                self.last_ts = ts
            elif ts < self.start_ts:
                self.start_ts = ts

        self.all_ts.append(ts)
        self.all_lens.append(float(pkt.payload_bytes))

        if is_forward:
            self.fwd_ts.append(ts)
            self.fwd_lens.append(float(pkt.payload_bytes))
            self.fwd_header_bytes += pkt.header_bytes
            if pkt.payload_bytes >= 1:
                self.act_data_pkt_fwd += 1
            if self.min_seg_size_forward is None or pkt.header_bytes < self.min_seg_size_forward:
                self.min_seg_size_forward = pkt.header_bytes
            if self.init_win_bytes_fwd == -1 and pkt.tcp_window >= 0:
                self.init_win_bytes_fwd = pkt.tcp_window
            self.fwd_psh_flags += pkt.flag_psh
            self.fwd_urg_flags += pkt.flag_urg
        else:
            self.bwd_ts.append(ts)
            self.bwd_lens.append(float(pkt.payload_bytes))
            self.bwd_header_bytes += pkt.header_bytes
            if self.init_win_bytes_bwd == -1 and pkt.tcp_window >= 0:
                self.init_win_bytes_bwd = pkt.tcp_window

        self.fin_count += pkt.flag_fin
        self.syn_count += pkt.flag_syn
        self.rst_count += pkt.flag_rst
        self.psh_count += pkt.flag_psh
        self.ack_count += pkt.flag_ack
        self.urg_count += pkt.flag_urg
        self.cwe_count += pkt.flag_cwe
        self.ece_count += pkt.flag_ece

    def to_completed_flow(self, data_source: str = "LIVE") -> CompletedFlow:
        """Tính toán đầy đủ 70 đặc trưng chuẩn CICFlowMeter khi kết thúc flow."""
        # Sắp xếp mốc thời gian phòng trường hợp gói tin đến lệch thứ tự nhỏ
        sorted_all_ts = sorted(self.all_ts)
        sorted_fwd_ts = sorted(self.fwd_ts)
        sorted_bwd_ts = sorted(self.bwd_ts)

        flow_duration_us = max(0.0, (sorted_all_ts[-1] - sorted_all_ts[0]) * 1_000_000.0)
        flow_duration_s = flow_duration_us / 1_000_000.0

        total_fwd_pkts = len(self.fwd_lens)
        total_bwd_pkts = len(self.bwd_lens)
        total_pkts = total_fwd_pkts + total_bwd_pkts

        total_len_fwd = float(sum(self.fwd_lens))
        total_len_bwd = float(sum(self.bwd_lens))
        total_bytes = total_len_fwd + total_len_bwd

        fwd_min, fwd_max, fwd_mean, fwd_std, _ = _safe_stats(self.fwd_lens)
        bwd_min, bwd_max, bwd_mean, bwd_std, _ = _safe_stats(self.bwd_lens)
        pkt_min, pkt_max, pkt_mean, pkt_std, pkt_var = _safe_stats(self.all_lens)

        # Tốc độ Bytes/s và Packets/s (nếu duration == 0 thì trả về 0.0 để tránh chia cho 0)
        if flow_duration_s > 0.0:
            flow_bytes_per_s = total_bytes / flow_duration_s
            flow_pkts_per_s = float(total_pkts) / flow_duration_s
            fwd_pkts_per_s = float(total_fwd_pkts) / flow_duration_s
            bwd_pkts_per_s = float(total_bwd_pkts) / flow_duration_s
        else:
            flow_bytes_per_s = 0.0
            flow_pkts_per_s = 0.0
            fwd_pkts_per_s = 0.0
            bwd_pkts_per_s = 0.0

        # Inter-Arrival Times (IAT) tính theo micro-giây (µs)
        flow_iats = [
            (sorted_all_ts[i + 1] - sorted_all_ts[i]) * 1_000_000.0
            for i in range(len(sorted_all_ts) - 1)
        ]
        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std, _ = _safe_stats(flow_iats)

        fwd_iats = [
            (sorted_fwd_ts[i + 1] - sorted_fwd_ts[i]) * 1_000_000.0
            for i in range(len(sorted_fwd_ts) - 1)
        ]
        fwd_iat_total = float(sum(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std, _ = _safe_stats(fwd_iats)

        bwd_iats = [
            (sorted_bwd_ts[i + 1] - sorted_bwd_ts[i]) * 1_000_000.0
            for i in range(len(sorted_bwd_ts) - 1)
        ]
        bwd_iat_total = float(sum(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std, _ = _safe_stats(bwd_iats)

        # Down/Up Ratio: trong CICFlowMeter là phép chia nguyên hoặc thực giữa Bwd packets và Fwd packets
        down_up_ratio = (
            float(total_bwd_pkts // total_fwd_pkts) if total_fwd_pkts > 0 else 0.0
        )

        # Average Packet Size trong CICFlowMeter = sum(all_lens_with_initial_dup) / total_pkts
        avg_packet_size = (
            float(sum(self.all_lens)) / float(total_pkts) if total_pkts > 0 else 0.0
        )
        avg_fwd_seg_size = fwd_mean
        avg_bwd_seg_size = bwd_mean

        # Subflow statistics
        sf_count = max(1, self.subflow_count)
        subflow_fwd_pkts = float(total_fwd_pkts // sf_count)
        subflow_fwd_bytes = float(int(total_len_fwd) // sf_count)
        subflow_bwd_pkts = float(total_bwd_pkts // sf_count)
        subflow_bwd_bytes = float(int(total_len_bwd) // sf_count)

        # Finalize active period hiện tại nếu có
        active_list = list(self.active_durations_us)
        final_active_us = (self.end_active_ts - self.start_active_ts) * 1_000_000.0
        if final_active_us > 0:
            active_list.append(final_active_us)

        act_min, act_max, act_mean, act_std, _ = _safe_stats(active_list)
        idle_min, idle_max, idle_mean, idle_std, _ = _safe_stats(self.idle_durations_us)

        min_seg_fwd = float(self.min_seg_size_forward if self.min_seg_size_forward is not None else 0)

        features: Dict[str, float] = {
            "Destination Port": float(self.dst_port),
            "Protocol": float(self.protocol),
            "Flow Duration": float(flow_duration_us),
            "Total Fwd Packets": float(total_fwd_pkts),
            "Total Backward Packets": float(total_bwd_pkts),
            "Total Length of Fwd Packets": float(total_len_fwd),
            "Total Length of Bwd Packets": float(total_len_bwd),
            "Fwd Packet Length Max": float(fwd_max),
            "Fwd Packet Length Min": float(fwd_min),
            "Fwd Packet Length Mean": float(fwd_mean),
            "Fwd Packet Length Std": float(fwd_std),
            "Bwd Packet Length Max": float(bwd_max),
            "Bwd Packet Length Min": float(bwd_min),
            "Bwd Packet Length Mean": float(bwd_mean),
            "Bwd Packet Length Std": float(bwd_std),
            "Flow Bytes/s": float(flow_bytes_per_s),
            "Flow Packets/s": float(flow_pkts_per_s),
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Total": float(fwd_iat_total),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Max": float(fwd_iat_max),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Total": float(bwd_iat_total),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": float(self.fwd_psh_flags),
            "Fwd URG Flags": float(self.fwd_urg_flags),
            "Fwd Header Length": float(self.fwd_header_bytes),
            "Bwd Header Length": float(self.bwd_header_bytes),
            "Fwd Packets/s": float(fwd_pkts_per_s),
            "Bwd Packets/s": float(bwd_pkts_per_s),
            "Min Packet Length": float(pkt_min),
            "Max Packet Length": float(pkt_max),
            "Packet Length Mean": float(pkt_mean),
            "Packet Length Std": float(pkt_std),
            "Packet Length Variance": float(pkt_var),
            "FIN Flag Count": float(self.fin_count),
            "SYN Flag Count": float(self.syn_count),
            "RST Flag Count": float(self.rst_count),
            "PSH Flag Count": float(self.psh_count),
            "ACK Flag Count": float(self.ack_count),
            "URG Flag Count": float(self.urg_count),
            "CWE Flag Count": float(self.cwe_count),
            "ECE Flag Count": float(self.ece_count),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_packet_size),
            "Avg Fwd Segment Size": float(avg_fwd_seg_size),
            "Avg Bwd Segment Size": float(avg_bwd_seg_size),
            "Subflow Fwd Packets": float(subflow_fwd_pkts),
            "Subflow Fwd Bytes": float(subflow_fwd_bytes),
            "Subflow Bwd Packets": float(subflow_bwd_pkts),
            "Subflow Bwd Bytes": float(subflow_bwd_bytes),
            "Init_Win_bytes_forward": float(self.init_win_bytes_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bytes_bwd),
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
            "min_seg_size_forward": float(min_seg_fwd),
            "Active Mean": float(act_mean),
            "Active Std": float(act_std),
            "Active Max": float(act_max),
            "Active Min": float(act_min),
            "Idle Mean": float(idle_mean),
            "Idle Std": float(idle_std),
            "Idle Max": float(idle_max),
            "Idle Min": float(idle_min),
        }

        flow_id = f"{self.src_ip}-{self.dst_ip}-{self.src_port}-{self.dst_port}-{self.protocol}"
        ts_iso = datetime.fromtimestamp(sorted_all_ts[-1], tz=timezone.utc).isoformat()

        return CompletedFlow(
            flow_id=flow_id,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            start_time=sorted_all_ts[0],
            end_time=sorted_all_ts[-1],
            timestamp_iso=ts_iso,
            packet_count=total_pkts,
            features=features,
            data_source=data_source,
        )


class FlowExtractor:
    """Bộ gom gói tin thành bidirectional network flow với quản lý timeout và giới hạn bộ nhớ."""

    def __init__(
        self,
        flow_timeout_seconds: float = 120.0,
        activity_timeout_seconds: float = 5.0,
        max_active_flows: int = 10000,
        on_flow_completed: Optional[Callable[[CompletedFlow], None]] = None,
    ) -> None:
        self.flow_timeout_seconds = flow_timeout_seconds
        self.activity_timeout_seconds = activity_timeout_seconds
        self.max_active_flows = max_active_flows
        self.on_flow_completed = on_flow_completed

        # Key chuẩn hóa hai chiều -> ActiveFlowState
        self._active_flows: Dict[Tuple[str, str, int, int, int], ActiveFlowState] = {}
        self.total_packets_processed: int = 0
        self.total_flows_completed: int = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._active_flows)

    def _bidirectional_key(
        self, pkt: ParsedPacket
    ) -> Tuple[Tuple[str, str, int, int, int], Tuple[str, str, int, int, int]]:
        """Tạo khóa forward và khóa reverse cho cùng một kết nối 5-tuple."""
        fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        rev_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)
        return fwd_key, rev_key

    def process_packet(
        self, pkt: ParsedPacket, data_source: str = "LIVE"
    ) -> List[CompletedFlow]:
        """Đưa một ParsedPacket vào bộ gom flow, trả về danh sách các flow đã kết thúc (nếu có)."""
        self.total_packets_processed += 1
        completed: List[CompletedFlow] = []

        fwd_key, rev_key = self._bidirectional_key(pkt)
        existing_key: Optional[Tuple[str, str, int, int, int]] = None
        if fwd_key in self._active_flows:
            existing_key = fwd_key
        elif rev_key in self._active_flows:
            existing_key = rev_key

        # Nếu flow đã tồn tại nhưng quá hạn flow_timeout_seconds -> đóng flow cũ, mở flow mới
        if existing_key is not None:
            state = self._active_flows[existing_key]
            if (pkt.timestamp - state.start_ts) > self.flow_timeout_seconds:
                done = self._finalize_flow(existing_key, data_source)
                completed.append(done)
                existing_key = None

        # Nếu chưa có flow, kiểm tra giới hạn bộ nhớ max_active_flows trước khi tạo mới
        if existing_key is None:
            if len(self._active_flows) >= self.max_active_flows:
                oldest_key = min(
                    self._active_flows.keys(), key=lambda k: self._active_flows[k].last_ts
                )
                completed.append(self._finalize_flow(oldest_key, data_source))

            state = ActiveFlowState(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                start_ts=pkt.timestamp,
                last_ts=pkt.timestamp,
            )
            state.add_packet(pkt, activity_timeout_s=self.activity_timeout_seconds)
            self._active_flows[fwd_key] = state
            existing_key = fwd_key
        else:
            state = self._active_flows[existing_key]
            state.add_packet(pkt, activity_timeout_s=self.activity_timeout_seconds)

        # Theo chuẩn CICFlowMeter, khi gặp cờ TCP RST hoặc FIN sau khi đã trao đổi dữ liệu, kết thúc flow
        if pkt.protocol == 6 and (pkt.flag_rst == 1 or (pkt.flag_fin == 1 and len(state.all_ts) >= 2)):
            completed.append(self._finalize_flow(existing_key, data_source))

        return completed

    def expire_timed_out_flows(
        self, current_ts: float, data_source: str = "LIVE"
    ) -> List[CompletedFlow]:
        """Đóng các flow đã vượt quá flow_timeout_seconds hoặc không có gói mới quá lâu."""
        expired_keys = [
            k
            for k, st in self._active_flows.items()
            if (current_ts - st.start_ts) > self.flow_timeout_seconds
            or (current_ts - st.last_ts) > self.flow_timeout_seconds
        ]
        return [self._finalize_flow(k, data_source) for k in expired_keys]

    def flush_all(self, data_source: str = "LIVE") -> List[CompletedFlow]:
        """Đóng và xuất toàn bộ các flow đang còn trong bộ đệm (dùng khi kết thúc đọc PCAP hoặc dừng capture)."""
        keys = list(self._active_flows.keys())
        return [self._finalize_flow(k, data_source) for k in keys]

    def reset(self) -> None:
        self._active_flows.clear()
        self.total_packets_processed = 0
        self.total_flows_completed = 0

    def _finalize_flow(
        self, key: Tuple[str, str, int, int, int], data_source: str
    ) -> CompletedFlow:
        state = self._active_flows.pop(key)
        flow = state.to_completed_flow(data_source=data_source)
        self.total_flows_completed += 1
        if self.on_flow_completed is not None:
            self.on_flow_completed(flow)
        return flow
