"""Temporal Window Buffer for CIC-DDoS2019 (8 flows per Source IP).

Chỉ áp dụng cho profile CIC-DDoS2019:
- Gom các network flow theo Source IP (grouping = "Source IP") trong cùng một monitoring session.
- Sắp xếp các flow trong buffer của mỗi Source IP theo timestamp tăng dần (xử lý được flow đến sai thứ tự).
- Window size = 8, Stride = 8 (cửa sổ không chồng lấn: mỗi khi đủ 8 flows sẽ xét và rút ra khỏi buffer).
- Điều kiện thời gian hợp lệ của cửa sổ:
  `0 < (end_timestamp - start_timestamp) <= 300` giây (max_window_seconds = 300).
  Lưu ý: Trong dữ liệu thực tế hoặc replay tốc độ cao khi các flow có cùng giây hoặc chênh lệch mili-giây
  rất nhỏ, nếu `0 < span <= 300` được thỏa mãn thì xuất cửa sổ hợp lệ; nếu `span > 300`, loại bỏ
  flow cũ nhất cho đến khi các flow còn lại nằm trong khoảng 300 giây; nếu 8 flows có timestamp
  hoàn toàn trùng nhau (`span == 0`), cộng một độ lệch vi mô theo thứ tự đến (1e-6 giây) giống
  thực tế gói tin tuần tự trên đường truyền hoặc giữ quy tắc kiểm tra nghiêm ngặt theo cấu hình.
- Không trộn flow từ các monitoring session khác nhau.
- Không sử dụng dữ liệu tương lai ngoài cửa sổ.
- Không padding bằng flow giả.
- Chỉ thực hiện inference khi đủ 8 flows hợp lệ. Nếu chưa đủ, trả trạng thái BUFFERING.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from backend.app.network.flow_extractor import CompletedFlow


@dataclass(frozen=True)
class TemporalWindowResult:
    """Kết quả sau khi đưa một flow vào bộ đệm Temporal Window của CIC-DDoS2019."""

    status: str  # "READY" hoặc "BUFFERING" hoặc "EXPIRED_DROPPED"
    source_ip: str
    session_id: str
    buffered_count: int
    required_window_size: int
    window_flows: Optional[List[CompletedFlow]] = None
    window_span_seconds: float = 0.0
    reason: Optional[str] = None


class TemporalWindowBuffer:
    """Quản lý cửa sổ thời gian 8 flows theo Source IP cho Temporal CNN-LSTM."""

    def __init__(
        self,
        window_size: int = 8,
        stride: int = 8,
        max_window_seconds: float = 300.0,
        session_id: str = "default",
        allow_zero_span_micro_offset: bool = True,
    ) -> None:
        if window_size != 8 or stride != 8:
            raise ValueError("CIC-DDoS2019 Temporal CNN-LSTM strictly requires window_size=8 and stride=8")
        self.window_size = window_size
        self.stride = stride
        self.max_window_seconds = max_window_seconds
        self.session_id = session_id
        self.allow_zero_span_micro_offset = allow_zero_span_micro_offset

        # Bộ đệm độc lập cho từng Source IP trong session hiện tại
        self._buffers: Dict[str, List[CompletedFlow]] = {}
        self._arrival_seq: int = 0
        self.total_windows_emitted: int = 0
        self.total_buffering_events: int = 0
        self.total_expired_drops: int = 0

    def reset(self, new_session_id: Optional[str] = None) -> None:
        """Xóa toàn bộ buffer khi bắt đầu session mới để không trộn flow giữa các session."""
        self._buffers.clear()
        self._arrival_seq = 0
        self.total_windows_emitted = 0
        self.total_buffering_events = 0
        self.total_expired_drops = 0
        if new_session_id is not None:
            self.session_id = new_session_id

    def get_buffer_count(self, src_ip: str) -> int:
        return len(self._buffers.get(src_ip, []))

    def get_all_buffer_counts(self) -> Dict[str, int]:
        return {ip: len(buf) for ip, buf in self._buffers.items() if buf}

    def add_flow(self, flow: CompletedFlow) -> TemporalWindowResult:
        """Thêm một flow đã hoàn thành vào buffer của Source IP tương ứng.

        Tự động sắp xếp theo timestamp để xử lý flow đến sai thứ tự.
        Chỉ trả về status="READY" kèm 8 flows khi đủ 8 flows thỏa mãn `0 < span <= 300s`.
        """
        self._arrival_seq += 1
        src_ip = flow.src_ip
        buf = self._buffers.setdefault(src_ip, [])

        # Nếu flow mới có timestamp trùng khít tới từng micro-giây với một flow đã có trong cùng IP
        # (thường gặp trong CSV CIC-DDoS2019 chỉ lưu timestamp tới độ phân giải giây hoặc mili-giây)
        # và allow_zero_span_micro_offset=True, cộng thêm offset 1e-6 * seq để bảo toàn thứ tự
        if self.allow_zero_span_micro_offset and any(abs(f.end_time - flow.end_time) < 1e-9 for f in buf):
            adjusted_end = flow.end_time + (self._arrival_seq * 1e-6)
            flow = CompletedFlow(
                flow_id=flow.flow_id,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                start_time=flow.start_time,
                end_time=adjusted_end,
                timestamp_iso=flow.timestamp_iso,
                packet_count=flow.packet_count,
                features=flow.features,
                ground_truth_label=flow.ground_truth_label,
                data_source=flow.data_source,
            )

        buf.append(flow)
        # Sắp xếp ổn định theo thời gian của flow (mergesort/timsort)
        buf.sort(key=lambda f: f.end_time)

        # Loại bỏ các flow quá cũ ở đầu buffer nếu khoảng cách tới flow mới nhất vượt quá max_window_seconds (300s)
        latest_ts = buf[-1].end_time
        dropped_old = 0
        while len(buf) > 1 and (latest_ts - buf[0].end_time) > self.max_window_seconds:
            buf.pop(0)
            dropped_old += 1
            self.total_expired_drops += 1

        if len(buf) < self.window_size:
            self.total_buffering_events += 1
            reason = (
                f"Dropped {dropped_old} expired flow(s) (> {self.max_window_seconds}s); "
                f"buffering {len(buf)}/{self.window_size}"
                if dropped_old > 0
                else f"Buffering {len(buf)}/{self.window_size} flows for Source IP {src_ip}"
            )
            return TemporalWindowResult(
                status="BUFFERING",
                source_ip=src_ip,
                session_id=self.session_id,
                buffered_count=len(buf),
                required_window_size=self.window_size,
                reason=reason,
            )

        # Lấy đúng 8 flows đầu tiên trong buffer (stride = 8, không chồng lấn)
        candidate = buf[: self.window_size]
        span = float(candidate[-1].end_time - candidate[0].end_time)

        if span <= 0.0 or span > self.max_window_seconds:
            # Nếu cửa sổ 8 flows không thỏa điều kiện 0 < span <= 300s, loại bỏ flow đầu tiên và tiếp tục đợi
            buf.pop(0)
            self.total_expired_drops += 1
            self.total_buffering_events += 1
            return TemporalWindowResult(
                status="BUFFERING",
                source_ip=src_ip,
                session_id=self.session_id,
                buffered_count=len(buf),
                required_window_size=self.window_size,
                window_span_seconds=span,
                reason=f"Window duration {span:.4f}s out of valid range (0, {self.max_window_seconds}s]",
            )

        # Cắt 8 flows ra khỏi buffer (stride = 8)
        del buf[: self.window_size]
        self.total_windows_emitted += 1

        return TemporalWindowResult(
            status="READY",
            source_ip=src_ip,
            session_id=self.session_id,
            buffered_count=len(buf),
            required_window_size=self.window_size,
            window_flows=candidate,
            window_span_seconds=span,
        )
