"""Gaussian Anomaly Detection auxiliary scorer.

Sử dụng mô hình LedoitWolf đã fit trên tập BENIGN (gaussian.joblib / gaussian_temporal.joblib).
Tính squared Mahalanobis distance (ledoit_wolf.mahalanobis(X)) và so sánh với ngưỡng
gaussian_threshold đã lưu trong config.json / artifact.

Nguyên tắc:
- Gaussian chỉ cung cấp anomaly_score và anomaly_flag (auxiliary_score).
- Không làm hard gate, không phủ quyết kết quả của CNN-LSTM và không tự sinh cảnh báo ATTACK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import numpy as np

from backend.app.core.model_registry import LoadedProfile


@dataclass(frozen=True)
class GaussianScoreResult:
    """Kết quả đánh giá bất thường thống kê Gaussian cho một mẫu."""

    anomaly_score: float
    threshold: float
    is_anomalous: bool


def compute_gaussian_scores(
    profile: LoadedProfile, scaled_inputs: np.ndarray
) -> List[GaussianScoreResult]:
    """Tính Gaussian anomaly score từ dữ liệu đã qua bước imputer + scaler của profile.

    - Với CIC-IDS2017: scaled_inputs có shape (Batch, 70).
    - Với CIC-DDoS2019: scaled_inputs có shape (Batch, 8, 66) hoặc (Batch, 66);
      theo đúng Cell 34 trên Colab, Gaussian của CIC-DDoS2019 sử dụng 66 features
      của flow cuối cùng trong cửa sổ: `X[:, -1, :]`.
    """
    if scaled_inputs.ndim == 3:
        # Lấy flow cuối cùng trong cửa sổ 8 flows (shape: Batch, 66)
        features_2d = scaled_inputs[:, -1, :]
    elif scaled_inputs.ndim == 2:
        features_2d = scaled_inputs
    elif scaled_inputs.ndim == 1:
        features_2d = scaled_inputs.reshape(1, -1)
    else:
        raise ValueError(f"Unsupported input shape for Gaussian scoring: {scaled_inputs.shape}")

    if features_2d.shape[1] != profile.n_features:
        raise ValueError(
            f"Gaussian scorer expected {profile.n_features} features, got {features_2d.shape[1]}"
        )

    gaussian_model = profile.gaussian_bundle["model"]
    threshold = float(profile.gaussian_threshold)

    # LedoitWolf.mahalanobis() trả về squared Mahalanobis distance đúng như Cell 20 & Cell 34
    distances = gaussian_model.mahalanobis(features_2d.astype(np.float64, copy=False))

    results: List[GaussianScoreResult] = []
    for dist in distances:
        score = float(dist)
        results.append(
            GaussianScoreResult(
                anomaly_score=score,
                threshold=threshold,
                is_anomalous=bool(score > threshold),
            )
        )
    return results
