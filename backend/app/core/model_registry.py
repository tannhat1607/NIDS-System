"""Model Registry for managing CNN-LSTM profiles and artifacts.

Quản lý việc tải và lưu trữ trên bộ nhớ (singleton) hai bộ trọng số CNN-LSTM độc lập:
- CIC-IDS2017: Feature-sequence CNN-LSTM (Batch, 70) -> 12 classes.
- CIC-DDoS2019: Temporal CNN-LSTM (Batch, 8, 66) -> 17 classes.

Đảm bảo:
- Chỉ load model lên CPU với model.eval().
- Không dùng chung preprocessor hay gộp trọng số giữa hai profile.
- Kiểm tra chặt chẽ tính toàn vẹn của feature_names, n_features, n_classes và label_mapping.
"""

from __future__ import annotations

import json
import logging
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import torch

from backend.app.config import ProfileSpec, get_profile_specs, settings

logger = logging.getLogger(__name__)


@dataclass
class LoadedProfile:
    """Lưu trữ toàn bộ tài nguyên đã load của một model profile."""

    profile_id: str
    spec: ProfileSpec
    model: torch.jit.ScriptModule
    preprocessor_bundle: Dict[str, Any]
    gaussian_bundle: Dict[str, Any]
    config: Dict[str, Any]
    label_mapping: Dict[int, str]
    feature_names: List[str]
    class_names: List[str]
    n_features: int
    n_classes: int
    benign_id: int
    window_size: int
    stride: int
    max_window_seconds: int
    gaussian_threshold: float
    input_type: str


class ModelRegistry:
    """Registry quản lý vòng đời và truy xuất các profile CNN-LSTM."""

    def __init__(self) -> None:
        self._specs: Dict[str, ProfileSpec] = get_profile_specs()
        self._loaded: Dict[str, LoadedProfile] = {}
        self._active_profile_id: str = settings.default_profile

    @property
    def active_profile_id(self) -> str:
        return self._active_profile_id

    def list_profiles(self) -> List[Dict[str, Any]]:
        """Trả về danh sách metadata của các profile hiện có."""
        profiles_info: List[Dict[str, Any]] = []
        for pid, spec in self._specs.items():
            loaded = self._loaded.get(pid)
            cfg_path = spec.artifact_dir / spec.config_filename
            cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
            profiles_info.append(
                {
                    "profile_id": pid,
                    "display_name": spec.display_name,
                    "description": spec.description,
                    "dataset": cfg.get("dataset", pid),
                    "architecture": cfg.get("architecture", "CNN-LSTM"),
                    "model_name": cfg.get("model", "CNNLSTM"),
                    "n_features": int(cfg.get("n_features", 0)),
                    "n_classes": int(cfg.get("n_classes", 0)),
                    "window_size": int(cfg.get("window_size", 1)),
                    "stride": int(cfg.get("stride", 1)),
                    "max_window_seconds": int(cfg.get("max_window_seconds", 300)),
                    "gaussian_threshold": float(cfg.get("gaussian_threshold", 0.0)),
                    "best_epoch": int(cfg.get("best_epoch", 0)),
                    "is_loaded": loaded is not None,
                    "is_active": pid == self._active_profile_id,
                    "artifact_dir": str(spec.artifact_dir),
                }
            )
        return profiles_info

    def load_profile(self, profile_id: str) -> LoadedProfile:
        """Load một profile vào bộ nhớ nếu chưa được load, hoặc trả về bản đã cache."""
        normalized_id = self._normalize_profile_id(profile_id)
        if normalized_id in self._loaded:
            return self._loaded[normalized_id]

        spec = self._specs[normalized_id]
        artifact_dir = spec.artifact_dir

        model_path = artifact_dir / spec.model_filename
        preprocessor_path = artifact_dir / spec.preprocessor_filename
        gaussian_path = artifact_dir / spec.gaussian_filename
        config_path = artifact_dir / spec.config_filename
        label_map_path = artifact_dir / spec.label_mapping_filename

        for required_path in (
            model_path,
            preprocessor_path,
            gaussian_path,
            config_path,
            label_map_path,
        ):
            if not required_path.exists():
                raise FileNotFoundError(
                    f"Missing required artifact for profile {normalized_id}: {required_path}"
                )

        # 1. Đọc config.json và label_mapping.json chính thức
        config_data: Dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
        raw_label_map: Dict[str, str] = json.loads(label_map_path.read_text(encoding="utf-8"))
        label_mapping: Dict[int, str] = {int(k): str(v) for k, v in raw_label_map.items()}

        # 2. Load preprocessor và Gaussian artifact độc lập của profile
        preprocessor_bundle: Dict[str, Any] = joblib.load(preprocessor_path)
        gaussian_bundle: Dict[str, Any] = joblib.load(gaussian_path)

        # 3. Load TorchScript model trên CPU và bật chế độ eval()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=FutureWarning)
            script_model = torch.jit.load(str(model_path), map_location="cpu")
        script_model.eval()

        # 4. Đối chiếu và xác thực tính nhất quán giữa config, preprocessor và label_mapping
        config_features = list(config_data["feature_names"])
        prep_features = list(preprocessor_bundle["feature_names"])
        n_features = int(config_data["n_features"])
        n_classes = int(config_data["n_classes"])

        if config_features != prep_features:
            raise ValueError(
                f"Feature names mismatch between config.json and preprocessor in {normalized_id}"
            )
        if len(config_features) != n_features:
            raise ValueError(
                f"Expected {n_features} features in {normalized_id}, got {len(config_features)}"
            )

        ordered_classes = [label_mapping[i] for i in range(len(label_mapping))]
        if ordered_classes != list(config_data["class_names"]):
            raise ValueError(
                f"Class names mismatch between config.json and label_mapping.json in {normalized_id}"
            )
        if len(ordered_classes) != n_classes:
            raise ValueError(
                f"Expected {n_classes} classes in {normalized_id}, got {len(ordered_classes)}"
            )

        if "imputer" not in preprocessor_bundle or "scaler" not in preprocessor_bundle:
            raise ValueError(f"Preprocessor bundle in {normalized_id} missing imputer or scaler")
        if "model" not in gaussian_bundle or "threshold" not in gaussian_bundle:
            raise ValueError(f"Gaussian bundle in {normalized_id} missing model or threshold")

        window_size = int(config_data.get("window_size", 1))
        stride = int(config_data.get("stride", 1))
        max_window_seconds = int(config_data.get("max_window_seconds", 300))
        benign_id = int(config_data.get("benign_id", 0))
        gaussian_threshold = float(
            config_data.get("gaussian_threshold", gaussian_bundle["threshold"])
        )
        input_type = str(
            config_data.get("input_type", "temporal_window" if window_size > 1 else "single_flow")
        )

        loaded_profile = LoadedProfile(
            profile_id=normalized_id,
            spec=spec,
            model=script_model,
            preprocessor_bundle=preprocessor_bundle,
            gaussian_bundle=gaussian_bundle,
            config=config_data,
            label_mapping=label_mapping,
            feature_names=config_features,
            class_names=ordered_classes,
            n_features=n_features,
            n_classes=n_classes,
            benign_id=benign_id,
            window_size=window_size,
            stride=stride,
            max_window_seconds=max_window_seconds,
            gaussian_threshold=gaussian_threshold,
            input_type=input_type,
        )

        self._loaded[normalized_id] = loaded_profile
        logger.info(
            "Loaded CNN-LSTM profile '%s' (%d features, %d classes, window=%d)",
            normalized_id,
            n_features,
            n_classes,
            window_size,
        )
        return loaded_profile

    def load_all_profiles(self) -> Dict[str, LoadedProfile]:
        """Load cả hai profile khi khởi động hệ thống để sẵn sàng phục vụ."""
        for pid in self._specs:
            self.load_profile(pid)
        return dict(self._loaded)

    def set_active_profile(self, profile_id: str) -> LoadedProfile:
        """Lựa chọn profile đang hoạt động và đảm bảo profile đó đã được load."""
        normalized_id = self._normalize_profile_id(profile_id)
        profile = self.load_profile(normalized_id)
        self._active_profile_id = normalized_id
        return profile

    def get_active_profile(self) -> LoadedProfile:
        """Lấy profile hiện đang được chọn."""
        return self.load_profile(self._active_profile_id)

    def get_profile(self, profile_id: Optional[str] = None) -> LoadedProfile:
        """Lấy một profile theo ID hoặc trả về active profile nếu không truyền."""
        target = profile_id or self._active_profile_id
        return self.load_profile(target)

    def _normalize_profile_id(self, profile_id: str) -> str:
        clean = profile_id.strip()
        if clean in ("CIC-IDS2017", "cic-ids2017"):
            return "CIC-IDS2017"
        if clean in ("CIC-DDoS2019", "CIC-DDoS2019_v2", "NIDS_Model_v1", "cic-ddos2019"):
            return "CIC-DDoS2019"
        raise KeyError(f"Unsupported model profile: {profile_id}. Allowed: CIC-IDS2017, CIC-DDoS2019")


# Singleton registry dùng chung toàn ứng dụng
model_registry = ModelRegistry()
