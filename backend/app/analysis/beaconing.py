r"""Statistical Beaconing Detection heuristic.

Phát hiện các kết nối có tính chu kỳ nghi ngờ (suspected beaconing) dựa trên phương pháp
thống kê cơ bản:
- Gom kết nối theo cặp (Source IP, Destination IP) và tùy chọn Destination Port.
- Lưu trữ lịch sử timestamp của các kết nối gần nhất (giới hạn bộ nhớ).
- Tính khoảng thời gian giữa các kết nối liên tiếp (inter-arrival intervals: \Delta t_i = t_{i+1} - t_i).
- Tính:
  + Connection count (N)
  + Mean interval (\mu)
  + Standard deviation (\sigma)
  + Coefficient of variation (CV = \sigma / \mu)
- Nếu số kết nối >= min_connections (mặc định 5), \mu >= min_interval_seconds (mặc định 0.5s)
  và CV <= cov_threshold (mặc định 0.25), đánh dấu là `suspected_beaconing = True`.

Nguyên tắc:
- Kết quả chỉ là `suspected beaconing` (tín hiệu nghi ngờ).
- Không kết luận kết nối định kỳ chắc chắn là botnet (vì có thể là NTP, heartbeat hợp lệ).
- Không tuyên bố sử dụng LSTM chuyên biệt cho Beaconing.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np


@dataclass(frozen=True)
class BeaconingCandidate:
    """Thông tin thống kê chu kỳ kết nối giữa một cặp (Source IP, Destination IP)."""

    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: int
    connection_count: int
    mean_interval: float
    std_interval: float
    coefficient_of_variation: float
    min_interval: float
    max_interval: float
    last_seen: str
    status: str  # "SUSPECTED_BEACONING" hoặc "NORMAL_PERIODIC" hoặc "IRREGULAR"
    is_suspected: bool
    session_id: str


class BeaconingDetector:
    """Bộ phân tích thống kê chu kỳ kết nối phát hiện dấu hiệu C2 Beaconing."""

    def __init__(
        self,
        min_connections: int = 5,
        cov_threshold: float = 0.25,
        min_interval_seconds: float = 0.2,
        max_pairs: int = 2000,
        max_timestamps_per_pair: int = 128,
    ) -> None:
        self.min_connections = max(3, min_connections)
        self.cov_threshold = cov_threshold
        self.min_interval_seconds = min_interval_seconds
        self.max_pairs = max_pairs
        self.max_timestamps_per_pair = max_timestamps_per_pair

        # Key: (src_ip, dst_ip) -> {"timestamps": List[float], "dst_port": int, "protocol": int, "session_id": str}
        self._history: Dict[Tuple[str, str], Dict[str, object]] = {}

    def reset(self) -> None:
        self._history.clear()

    def record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        timestamp: float,
        dst_port: int = 0,
        protocol: int = 6,
        session_id: str = "default",
    ) -> Optional[BeaconingCandidate]:
        """Ghi nhận một kết nối mới và tính toán chỉ số thống kê chu kỳ của cặp IP."""
        key = (src_ip, dst_ip)

        if key not in self._history and len(self._history) >= self.max_pairs:
            # Giải phóng cặp cũ nhất khi vượt quá giới hạn bộ nhớ
            oldest_key = next(iter(self._history.keys()))
            self._history.pop(oldest_key, None)

        entry = self._history.get(key)
        if entry is None:
            ts_list: List[float] = [float(timestamp)]
            self._history[key] = {
                "timestamps": ts_list,
                "dst_port": int(dst_port),
                "protocol": int(protocol),
                "session_id": session_id,
            }
            return None

        ts_list = entry["timestamps"]  # type: ignore[assignment]
        ts_list.append(float(timestamp))
        if len(ts_list) > self.max_timestamps_per_pair:
            del ts_list[: len(ts_list) - self.max_timestamps_per_pair]

        entry["dst_port"] = int(dst_port)
        entry["protocol"] = int(protocol)
        entry["session_id"] = session_id

        return self._evaluate_pair(src_ip, dst_ip, entry)

    def get_candidates(self, only_suspected: bool = False) -> List[BeaconingCandidate]:
        """Trả về danh sách các cặp kết nối đã đủ số lượng mẫu để đánh giá chu kỳ."""
        candidates: List[BeaconingCandidate] = []
        for (src_ip, dst_ip), entry in self._history.items():
            cand = self._evaluate_pair(src_ip, dst_ip, entry)
            if cand is not None:
                if not only_suspected or cand.is_suspected:
                    candidates.append(cand)

        # Sắp xếp ưu tiên các kết nối nghi ngờ beaconing có CV thấp nhất và nhiều kết nối nhất
        candidates.sort(
            key=lambda c: (not c.is_suspected, c.coefficient_of_variation, -c.connection_count)
        )
        return candidates

    def _evaluate_pair(
        self, src_ip: str, dst_ip: str, entry: Dict[str, object]
    ) -> Optional[BeaconingCandidate]:
        ts_list: List[float] = sorted(entry["timestamps"])  # type: ignore[arg-type]
        n_conn = len(ts_list)
        if n_conn < self.min_connections:
            return None

        diffs = np.diff(np.asarray(ts_list, dtype=np.float64))
        # Chỉ xét các khoảng thời gian dương để tránh chia cho 0 khi các gói burst cùng tích tắc
        positive_diffs = diffs[diffs > 1e-4]
        if len(positive_diffs) < (self.min_connections - 1):
            return None

        mean_int = float(np.mean(positive_diffs))
        std_int = float(np.std(positive_diffs, ddof=1)) if len(positive_diffs) > 1 else 0.0
        min_int = float(np.min(positive_diffs))
        max_int = float(np.max(positive_diffs))

        if mean_int <= 0.0:
            return None

        cov = float(std_int / mean_int)
        if not math.isfinite(cov):
            return None

        is_suspected = bool(
            n_conn >= self.min_connections
            and mean_int >= self.min_interval_seconds
            and cov <= self.cov_threshold
        )
        status = "SUSPECTED_BEACONING" if is_suspected else "IRREGULAR"
        last_seen_iso = datetime.fromtimestamp(ts_list[-1], tz=timezone.utc).isoformat()

        return BeaconingCandidate(
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=int(entry.get("dst_port", 0)),  # type: ignore[arg-type]
            protocol=int(entry.get("protocol", 6)),  # type: ignore[arg-type]
            connection_count=n_conn,
            mean_interval=round(mean_int, 4),
            std_interval=round(std_int, 4),
            coefficient_of_variation=round(cov, 4),
            min_interval=round(min_int, 4),
            max_interval=round(max_int, 4),
            last_seen=last_seen_iso,
            status=status,
            is_suspected=is_suspected,
            session_id=str(entry.get("session_id", "default")),
        )
