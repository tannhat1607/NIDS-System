"""SQLite database repository using parameterized SQL queries.

Lưu trữ bền vững:
1. `monitoring_sessions`: Lịch sử các phiên giám sát (session_id, profile_id, data_source, interface,
   started_at, stopped_at, status, total_packets, total_flows, total_inferences, total_alerts).
2. `attack_alerts`: Toàn bộ các bản ghi phát hiện và cảnh báo (hỗ trợ tìm kiếm, lọc theo IP,
   thời gian, loại tấn công, profile, trạng thái BENIGN/ATTACK, phân trang và xuất CSV).
3. `beaconing_candidates`: Các cặp kết nối nghi ngờ C2 Beaconing.
4. `system_events`: Nhật ký sự kiện hệ thống có cấu trúc.

Tuyệt đối chỉ sử dụng Parameterized SQL (`?`) để chống SQL Injection.
"""

from __future__ import annotations

import csv
import io
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.analysis.beaconing import BeaconingCandidate
from backend.app.config import DB_PATH
from backend.app.core.detection_engine import DetectionRecord


class SQLiteRepository:
    """Lớp truy xuất cơ sở dữ liệu SQLite an toàn đa luồng với Parameterized SQL."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path or DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitoring_sessions (
                    session_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    data_source TEXT NOT NULL,
                    interface_or_file TEXT,
                    started_at TEXT NOT NULL,
                    stopped_at TEXT,
                    status TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    total_flows INTEGER DEFAULT 0,
                    total_inferences INTEGER DEFAULT 0,
                    total_alerts INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS attack_alerts (
                    alert_id TEXT PRIMARY KEY,
                    detected_at TEXT NOT NULL,
                    flow_timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    detection_status TEXT NOT NULL,
                    predicted_attack_type TEXT NOT NULL,
                    class_score REAL NOT NULL,
                    attack_score REAL NOT NULL,
                    gaussian_anomaly_score REAL NOT NULL,
                    gaussian_threshold REAL NOT NULL,
                    gaussian_is_anomalous INTEGER NOT NULL,
                    inference_latency_ms REAL NOT NULL,
                    dataset_profile TEXT NOT NULL,
                    monitoring_session TEXT NOT NULL,
                    data_source TEXT NOT NULL,
                    buffered_flows INTEGER DEFAULT 1,
                    required_window_size INTEGER DEFAULT 1,
                    ground_truth_label TEXT,
                    note TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON attack_alerts(detected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON attack_alerts(detection_status);
                CREATE INDEX IF NOT EXISTS idx_alerts_profile ON attack_alerts(dataset_profile);
                CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON attack_alerts(source_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON attack_alerts(destination_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON attack_alerts(predicted_attack_type);

                CREATE TABLE IF NOT EXISTS beaconing_candidates (
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    connection_count INTEGER NOT NULL,
                    mean_interval REAL NOT NULL,
                    std_interval REAL NOT NULL,
                    coefficient_of_variation REAL NOT NULL,
                    min_interval REAL NOT NULL,
                    max_interval REAL NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_suspected INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    PRIMARY KEY (source_ip, destination_ip, session_id)
                );

                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    session_id TEXT
                );
                """
            )

    def create_session(
        self,
        session_id: str,
        profile_id: str,
        data_source: str,
        interface_or_file: str = "",
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO monitoring_sessions
                (session_id, profile_id, data_source, interface_or_file, started_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, profile_id, data_source, interface_or_file, now_iso, "RUNNING"),
            )

    def finalize_session(
        self,
        session_id: str,
        total_packets: int,
        total_flows: int,
        total_inferences: int,
        total_alerts: int,
        status: str = "COMPLETED",
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE monitoring_sessions
                SET stopped_at = ?, status = ?, total_packets = ?, total_flows = ?,
                    total_inferences = ?, total_alerts = ?
                WHERE session_id = ?
                """,
                (
                    now_iso,
                    status,
                    int(total_packets),
                    int(total_flows),
                    int(total_inferences),
                    int(total_alerts),
                    session_id,
                ),
            )

    def insert_detection(self, record: DetectionRecord) -> None:
        """Lưu kết quả phát hiện (ATTACK hoặc BENIGN) vào bảng attack_alerts."""
        if record.detection_status == "BUFFERING":
            # Không lưu trạng thái trung gian BUFFERING vào lịch sử cảnh báo SQLite
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO attack_alerts (
                    alert_id, detected_at, flow_timestamp, source_ip, destination_ip,
                    source_port, destination_port, protocol, detection_status,
                    predicted_attack_type, class_score, attack_score,
                    gaussian_anomaly_score, gaussian_threshold, gaussian_is_anomalous,
                    inference_latency_ms, dataset_profile, monitoring_session,
                    data_source, buffered_flows, required_window_size,
                    ground_truth_label, note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.alert_id,
                    record.detected_at,
                    record.flow_timestamp,
                    record.source_ip,
                    record.destination_ip,
                    int(record.source_port),
                    int(record.destination_port),
                    int(record.protocol),
                    record.detection_status,
                    record.predicted_attack_type,
                    float(record.class_score),
                    float(record.attack_score),
                    float(record.gaussian_anomaly_score),
                    float(record.gaussian_threshold),
                    1 if record.gaussian_is_anomalous else 0,
                    float(record.inference_latency_ms),
                    record.dataset_profile,
                    record.monitoring_session,
                    record.data_source,
                    int(record.buffered_flows),
                    int(record.required_window_size),
                    record.ground_truth_label,
                    record.note,
                ),
            )

    def upsert_beaconing_candidates(self, candidates: List[BeaconingCandidate]) -> None:
        if not candidates:
            return
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO beaconing_candidates (
                    source_ip, destination_ip, destination_port, protocol,
                    connection_count, mean_interval, std_interval,
                    coefficient_of_variation, min_interval, max_interval,
                    last_seen, status, is_suspected, session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        c.source_ip,
                        c.destination_ip,
                        int(c.destination_port),
                        int(c.protocol),
                        int(c.connection_count),
                        float(c.mean_interval),
                        float(c.std_interval),
                        float(c.coefficient_of_variation),
                        float(c.min_interval),
                        float(c.max_interval),
                        c.last_seen,
                        c.status,
                        1 if c.is_suspected else 0,
                        c.session_id,
                    )
                    for c in candidates
                ],
            )

    def log_event(
        self,
        event_type: str,
        message: str,
        severity: str = "INFO",
        session_id: Optional[str] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO system_events (created_at, event_type, severity, message, session_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now_iso, event_type, severity, message, session_id),
            )

    def query_alerts(
        self,
        page: int = 1,
        page_size: int = 25,
        detection_status: Optional[str] = None,
        dataset_profile: Optional[str] = None,
        attack_type: Optional[str] = None,
        ip_filter: Optional[str] = None,
        data_source: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Truy vấn danh sách cảnh báo hỗ trợ tìm kiếm, lọc và phân trang bằng Parameterized SQL."""
        where_clauses: List[str] = []
        params: List[Any] = []

        if detection_status and detection_status != "ALL":
            where_clauses.append("detection_status = ?")
            params.append(detection_status)

        if dataset_profile and dataset_profile != "ALL":
            where_clauses.append("dataset_profile = ?")
            params.append(dataset_profile)

        if attack_type and attack_type != "ALL":
            where_clauses.append("predicted_attack_type = ?")
            params.append(attack_type)

        if data_source and data_source != "ALL":
            where_clauses.append("data_source = ?")
            params.append(data_source)

        if ip_filter and ip_filter.strip():
            ip_val = f"%{ip_filter.strip()}%"
            where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
            params.extend([ip_val, ip_val])

        if start_time and start_time.strip():
            where_clauses.append("detected_at >= ?")
            params.append(start_time.strip())

        if end_time and end_time.strip():
            where_clauses.append("detected_at <= ?")
            params.append(end_time.strip())

        if search_query and search_query.strip():
            q_val = f"%{search_query.strip()}%"
            where_clauses.append(
                "(source_ip LIKE ? OR destination_ip LIKE ? OR predicted_attack_type LIKE ? OR alert_id LIKE ?)"
            )
            params.extend([q_val, q_val, q_val, q_val])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        safe_page = max(1, int(page))
        safe_size = min(500, max(1, int(page_size)))
        offset = (safe_page - 1) * safe_size

        with self._lock, self._connect() as conn:
            count_row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM attack_alerts {where_sql}", params
            ).fetchone()
            total_count = int(count_row["cnt"]) if count_row else 0

            rows = conn.execute(
                f"""
                SELECT * FROM attack_alerts
                {where_sql}
                ORDER BY detected_at DESC
                LIMIT ? OFFSET ?
                """,
                [*params, safe_size, offset],
            ).fetchall()

        items = [self._row_to_alert_dict(r) for r in rows]
        return items, total_count

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM attack_alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        return self._row_to_alert_dict(row) if row else None

    def get_attack_statistics(self, dataset_profile: Optional[str] = None) -> Dict[str, Any]:
        """Tính thống kê số lượng BENIGN/ATTACK, phân phối loại tấn công và timeline."""
        where_sql = ""
        params: List[Any] = []
        if dataset_profile and dataset_profile != "ALL":
            where_sql = "WHERE dataset_profile = ?"
            params.append(dataset_profile)

        with self._lock, self._connect() as conn:
            status_rows = conn.execute(
                f"""
                SELECT detection_status, COUNT(*) AS cnt
                FROM attack_alerts
                {where_sql}
                GROUP BY detection_status
                """,
                params,
            ).fetchall()

            dist_rows = conn.execute(
                f"""
                SELECT predicted_attack_type, detection_status, COUNT(*) AS cnt,
                       AVG(class_score) AS avg_score, AVG(inference_latency_ms) AS avg_latency
                FROM attack_alerts
                {where_sql}
                GROUP BY predicted_attack_type, detection_status
                ORDER BY cnt DESC
                """,
                params,
            ).fetchall()

            timeline_rows = conn.execute(
                f"""
                SELECT SUBSTR(detected_at, 1, 16) AS time_bucket,
                       SUM(CASE WHEN detection_status = 'ATTACK' THEN 1 ELSE 0 END) AS attack_count,
                       SUM(CASE WHEN detection_status = 'BENIGN' THEN 1 ELSE 0 END) AS benign_count
                FROM attack_alerts
                {where_sql}
                GROUP BY time_bucket
                ORDER BY time_bucket DESC
                LIMIT 30
                """,
                params,
            ).fetchall()

        status_counts = {str(r["detection_status"]): int(r["cnt"]) for r in status_rows}
        total_attacks = status_counts.get("ATTACK", 0)
        total_benign = status_counts.get("BENIGN", 0)
        total_records = total_attacks + total_benign

        distribution = [
            {
                "attack_type": str(r["predicted_attack_type"]),
                "detection_status": str(r["detection_status"]),
                "count": int(r["cnt"]),
                "avg_score": round(float(r["avg_score"] or 0.0), 4),
                "avg_latency_ms": round(float(r["avg_latency"] or 0.0), 4),
            }
            for r in dist_rows
        ]

        timeline = [
            {
                "time_bucket": str(r["time_bucket"]),
                "attack_count": int(r["attack_count"] or 0),
                "benign_count": int(r["benign_count"] or 0),
            }
            for r in reversed(timeline_rows)
        ]

        return {
            "total_records": total_records,
            "total_attacks": total_attacks,
            "total_benign": total_benign,
            "attack_ratio": round(total_attacks / max(1, total_records), 4),
            "benign_ratio": round(total_benign / max(1, total_records), 4),
            "distribution": distribution,
            "timeline": timeline,
        }

    def export_alerts_csv(
        self,
        detection_status: Optional[str] = None,
        dataset_profile: Optional[str] = None,
        attack_type: Optional[str] = None,
        ip_filter: Optional[str] = None,
    ) -> str:
        """Xuất danh sách cảnh báo ra chuỗi CSV để người dùng tải xuống."""
        items, _ = self.query_alerts(
            page=1,
            page_size=5000,
            detection_status=detection_status,
            dataset_profile=dataset_profile,
            attack_type=attack_type,
            ip_filter=ip_filter,
        )
        output = io.StringIO()
        fieldnames = [
            "alert_id",
            "detected_at",
            "flow_timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "detection_status",
            "predicted_attack_type",
            "class_score",
            "attack_score",
            "gaussian_anomaly_score",
            "gaussian_threshold",
            "gaussian_is_anomalous",
            "inference_latency_ms",
            "dataset_profile",
            "monitoring_session",
            "data_source",
            "ground_truth_label",
            "note",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            writer.writerow({k: item.get(k, "") for k in fieldnames})
        return output.getvalue()

    def _row_to_alert_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["gaussian_is_anomalous"] = bool(d.get("gaussian_is_anomalous"))
        return d


# Singleton repository
db_repository = SQLiteRepository()
