"""Configuration management for NIDS Backend.

Quản lý cấu hình đường dẫn artifact, database và tham số giám sát mạng.
Tự động nhận diện thư mục artifact thực tế trong workspace (CIC-IDS2017 và NIDS_Model_v1 / CIC-DDoS2019).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

BASE_DIR = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = Path(os.getenv("NIDS_ARTIFACTS_DIR", str(BASE_DIR / "artifacts")))
DATA_DIR = Path(os.getenv("NIDS_DATA_DIR", str(BASE_DIR / "data")))
LOGS_DIR = Path(os.getenv("NIDS_LOGS_DIR", str(BASE_DIR / "logs")))
DB_PATH = Path(os.getenv("NIDS_DB_PATH", str(DATA_DIR / "nids.db")))


def resolve_profile_dir(profile_id: str) -> Path:
    """Xác định thư mục artifact thực tế cho từng model profile.

    Không giả định cứng tên thư mục nếu workspace dùng NIDS_Model_v1 cho CIC-DDoS2019.
    """
    if profile_id == "CIC-IDS2017":
        candidate = ARTIFACTS_DIR / "CIC-IDS2017"
        if candidate.exists():
            return candidate
    elif profile_id in ("CIC-DDoS2019", "CIC-DDoS2019_v2", "NIDS_Model_v1"):
        for folder_name in ("CIC-DDoS2019", "NIDS_Model_v1", "CIC-DDoS2019_v2"):
            candidate = ARTIFACTS_DIR / folder_name
            if candidate.exists():
                return candidate
    raise FileNotFoundError(f"Artifact directory not found for profile: {profile_id}")


@dataclass(frozen=True)
class ProfileSpec:
    """Thông tin định danh và file artifact của từng profile CNN-LSTM."""

    profile_id: str
    display_name: str
    description: str
    artifact_dir: Path
    model_filename: str = "cnn_lstm.pt"
    checkpoint_filename: str = "best.pt"
    preprocessor_filename: str = "preprocessor.joblib"
    gaussian_filename: str = "gaussian.joblib"
    config_filename: str = "config.json"
    label_mapping_filename: str = "label_mapping.json"


def get_profile_specs() -> Dict[str, ProfileSpec]:
    """Trả về cấu hình hai profile chính thức: CIC-IDS2017 (mặc định) và CIC-DDoS2019."""
    cic_ids_dir = resolve_profile_dir("CIC-IDS2017")
    cic_ddos_dir = resolve_profile_dir("CIC-DDoS2019")

    return {
        "CIC-IDS2017": ProfileSpec(
            profile_id="CIC-IDS2017",
            display_name="CIC-IDS2017 (General NIDS - 70 Features, 12 Classes)",
            description=(
                "Feature-sequence CNN-LSTM phân loại từng network flow (single_flow), "
                "phát hiện 11 nhóm tấn công mạng phổ biến và lưu lượng BENIGN."
            ),
            artifact_dir=cic_ids_dir,
            preprocessor_filename="preprocessor.joblib",
            gaussian_filename="gaussian.joblib",
        ),
        "CIC-DDoS2019": ProfileSpec(
            profile_id="CIC-DDoS2019",
            display_name="CIC-DDoS2019 V2 (Temporal DDoS - 8x66 Features, 17 Classes)",
            description=(
                "Temporal CNN-LSTM phân tích cửa sổ 8 flows liên tiếp theo Source IP "
                "(window_size=8, stride=8, max_window_seconds=300), chuyên sâu DoS/DDoS."
            ),
            artifact_dir=cic_ddos_dir,
            preprocessor_filename="temporal_preprocessor.joblib",
            gaussian_filename="gaussian_temporal.joblib",
        ),
    }


@dataclass
class AppSettings:
    """Cấu hình toàn cục cho hệ thống NIDS."""

    host: str = field(default_factory=lambda: os.getenv("NIDS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("NIDS_PORT", "8000")))
    default_profile: str = "CIC-IDS2017"
    flow_timeout_seconds: float = 120.0
    activity_timeout_seconds: float = 5.0
    max_active_flows: int = 10000
    inference_queue_maxsize: int = 5000
    max_graph_nodes: int = 500
    graph_retention_seconds: float = 1800.0
    beaconing_min_connections: int = 5
    beaconing_cov_threshold: float = 0.25


settings = AppSettings()
