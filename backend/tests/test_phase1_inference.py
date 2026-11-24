"""Unit tests for Phase 1: Model Loading, Preprocessing, Gaussian Scoring, and AI Inference."""

from __future__ import annotations

import numpy as np
import pytest
import torch
from torch import nn

from backend.app.core.inference import InferenceEngine
from backend.app.core.model_registry import ModelRegistry
from backend.app.core.preprocessing import (
    FeatureCompatibilityError,
    preprocess_single_flow_batch,
    preprocess_temporal_window_batch,
)


class FlowFeatureCNNLSTM(nn.Module):
    """Kiến trúc gốc từ Cell 17 / Cell 36.3 trên Colab để đối chiếu với TorchScript."""

    def __init__(self, n_classes: int = 12) -> None:
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=5, padding=2),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(32, 48, kernel_size=3, padding=1),
            nn.BatchNorm1d(48),
            nn.ReLU(),
        )
        self.lstm = nn.LSTM(
            input_size=48,
            hidden_size=64,
            num_layers=1,
            batch_first=True,
            bidirectional=False,
        )
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(64, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.cnn(x.unsqueeze(1))
        z = z.transpose(1, 2)
        z, _ = self.lstm(z)
        return self.classifier(z[:, -1, :])


class TemporalCNNLSTM(nn.Module):
    """Kiến trúc gốc từ Cell 31 / Cell 35 trên Colab để đối chiếu với TorchScript."""

    def __init__(self, n_classes: int = 17) -> None:
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(1, 32, 5, padding=2),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(32, 64, 3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.AdaptiveAvgPool1d(4),
            nn.Flatten(),
        )
        self.flow_embedding = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
        )
        self.lstm = nn.LSTM(128, 128, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b, t, f = x.shape
        x = self.cnn(x.reshape(b * t, 1, f))
        x = self.flow_embedding(x).reshape(b, t, 128)
        x, _ = self.lstm(x)
        return self.classifier(x[:, -1, :])


@pytest.fixture(scope="module")
def registry() -> ModelRegistry:
    reg = ModelRegistry()
    reg.load_all_profiles()
    return reg


@pytest.fixture(scope="module")
def engine(registry: ModelRegistry) -> InferenceEngine:
    return InferenceEngine(registry)


def test_both_profiles_load_correctly(registry: ModelRegistry) -> None:
    p_ids = registry.load_profile("CIC-IDS2017")
    assert p_ids.n_features == 70
    assert p_ids.n_classes == 12
    assert p_ids.window_size == 1
    assert p_ids.stride == 1
    assert p_ids.benign_id == 0
    assert p_ids.class_names[0] == "BENIGN"
    assert len(p_ids.feature_names) == 70

    p_ddos = registry.load_profile("CIC-DDoS2019")
    assert p_ddos.n_features == 66
    assert p_ddos.n_classes == 17
    assert p_ddos.window_size == 8
    assert p_ddos.stride == 8
    assert p_ddos.max_window_seconds == 300
    assert p_ddos.benign_id == 0
    assert p_ddos.class_names[0] == "BENIGN"
    assert len(p_ddos.feature_names) == 66


def test_torchscript_matches_colab_checkpoint_weights(registry: ModelRegistry) -> None:
    """Kiểm tra tính nhất quán tuyệt đối giữa cnn_lstm.pt và best.pt từ Colab."""
    # 1. CIC-IDS2017
    p_ids = registry.get_profile("CIC-IDS2017")
    ckpt_ids = torch.load(
        p_ids.spec.artifact_dir / "best.pt", map_location="cpu", weights_only=True
    )
    eager_ids = FlowFeatureCNNLSTM(n_classes=p_ids.n_classes)
    eager_ids.load_state_dict(ckpt_ids["model_state"], strict=True)
    eager_ids.eval()

    # Sử dụng vector mean của scaler (tương đương 0 sau chuẩn hóa) và một vài biến thiên thực tế
    scaler_mean_ids = p_ids.preprocessor_bundle["scaler"].mean_.astype(np.float32)
    scaler_scale_ids = p_ids.preprocessor_bundle["scaler"].scale_.astype(np.float32)
    raw_batch_ids = np.stack(
        [
            scaler_mean_ids,
            scaler_mean_ids + 0.5 * scaler_scale_ids,
            scaler_mean_ids - 0.5 * scaler_scale_ids,
        ],
        axis=0,
    )
    _, tensor_ids = preprocess_single_flow_batch(p_ids, raw_batch_ids)

    with torch.inference_mode():
        out_eager_ids = eager_ids(tensor_ids)
        out_jit_ids = p_ids.model(tensor_ids)
        assert torch.allclose(out_eager_ids, out_jit_ids, atol=1e-5, rtol=1e-4)

    # 2. CIC-DDoS2019
    p_ddos = registry.get_profile("CIC-DDoS2019")
    ckpt_ddos = torch.load(
        p_ddos.spec.artifact_dir / "best.pt", map_location="cpu", weights_only=True
    )
    eager_ddos = TemporalCNNLSTM(n_classes=p_ddos.n_classes)
    eager_ddos.load_state_dict(ckpt_ddos["model_state_dict"], strict=True)
    eager_ddos.eval()

    scaler_mean_ddos = p_ddos.preprocessor_bundle["scaler"].mean_.astype(np.float32)
    raw_window_ddos = np.tile(scaler_mean_ddos, (2, 8, 1))
    _, tensor_ddos = preprocess_temporal_window_batch(p_ddos, raw_window_ddos)

    with torch.inference_mode():
        out_eager_ddos = eager_ddos(tensor_ddos)
        out_jit_ddos = p_ddos.model(tensor_ddos)
        assert torch.allclose(out_eager_ddos, out_jit_ddos, atol=1e-5, rtol=1e-4)


def test_missing_unimplemented_feature_raises_error(registry: ModelRegistry) -> None:
    """Đảm bảo không tự động điền 0 khi thiếu cột đặc trưng."""
    p_ids = registry.get_profile("CIC-IDS2017")
    incomplete_flow = {"Destination Port": 80, "Protocol": 6}
    with pytest.raises(FeatureCompatibilityError):
        preprocess_single_flow_batch(p_ids, [incomplete_flow])


def test_nan_and_inf_handled_by_imputer(
    registry: ModelRegistry, engine: InferenceEngine
) -> None:
    """Đảm bảo giá trị NaN và Inf hợp lệ trong đặc trưng được xử lý bởi SimpleImputer."""
    p_ids = registry.get_profile("CIC-IDS2017")
    medians = p_ids.preprocessor_bundle["imputer"].statistics_
    flow_dict = {feat: float(medians[i]) for i, feat in enumerate(p_ids.feature_names)}
    flow_dict["Flow Bytes/s"] = float("inf")
    flow_dict["Flow Packets/s"] = float("nan")

    pred = engine.predict_single_flow(flow_dict, profile_id="CIC-IDS2017")
    assert pred.profile_id == "CIC-IDS2017"
    assert pred.predicted_label in p_ids.class_names
    assert pred.detection_status in ("BENIGN", "ATTACK")
    assert 0.0 <= pred.class_score <= 1.0
    assert 0.0 <= pred.attack_score <= 1.0
    assert np.isclose(pred.attack_score + pred.benign_score, 1.0, atol=1e-4)
    assert pred.latency_ms > 0.0
    assert np.isfinite(pred.gaussian_anomaly_score)


def test_temporal_window_inference(
    registry: ModelRegistry, engine: InferenceEngine
) -> None:
    """Kiểm tra inference cho cửa sổ 8 flows của CIC-DDoS2019."""
    p_ddos = registry.get_profile("CIC-DDoS2019")
    medians = p_ddos.preprocessor_bundle["imputer"].statistics_
    single_flow = {feat: float(medians[i]) for i, feat in enumerate(p_ddos.feature_names)}
    window_8_flows = [dict(single_flow) for _ in range(8)]

    pred = engine.predict_temporal_window(window_8_flows, profile_id="CIC-DDoS2019")
    assert pred.profile_id == "CIC-DDoS2019"
    assert pred.predicted_label in p_ddos.class_names
    assert pred.detection_status in ("BENIGN", "ATTACK")
    assert 0.0 <= pred.class_score <= 1.0
    assert np.isclose(pred.attack_score + pred.benign_score, 1.0, atol=1e-4)
    assert pred.gaussian_threshold == pytest.approx(185.020328, rel=1e-4)
    assert pred.latency_ms > 0.0
