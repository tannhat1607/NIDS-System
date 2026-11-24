"""AI Inference Engine for CNN-LSTM models.

Thực hiện suy luận (inference) với TorchScript CNN-LSTM trên CPU:
- Sử dụng torch.inference_mode() và model.eval().
- Tính logits -> Softmax probabilities -> Argmax class index.
- Ánh xạ class index sang tên lớp qua label_mapping chính thức.
- Xác định trạng thái BENIGN hoặc ATTACK theo quy tắc argmax giống thực nghiệm trên Colab:
  + class_index == benign_id (0) -> BENIGN
  + class_index != benign_id     -> ATTACK
- Tính class_score (xác suất Softmax của lớp dự đoán) và attack_score (tổng xác suất Softmax
  của tất cả các lớp ATTACK = 1.0 - P(BENIGN)).
- Tính kèm Gaussian anomaly score (bổ trợ, không phủ quyết CNN-LSTM).
- Đo thời gian suy luận (inference latency) bằng mili-giây (ms).
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import numpy as np
import torch

from backend.app.analysis.gaussian import GaussianScoreResult, compute_gaussian_scores
from backend.app.core.model_registry import LoadedProfile, ModelRegistry, model_registry
from backend.app.core.preprocessing import (
    preprocess_single_flow_batch,
    preprocess_temporal_window_batch,
)


@dataclass(frozen=True)
class InferencePrediction:
    """Kết quả suy luận đầy đủ cho một flow (CIC-IDS2017) hoặc một cửa sổ 8 flows (CIC-DDoS2019)."""

    profile_id: str
    dataset: str
    predicted_class_id: int
    predicted_label: str
    detection_status: str  # "BENIGN" hoặc "ATTACK"
    class_score: float
    attack_score: float
    benign_score: float
    gaussian_anomaly_score: float
    gaussian_threshold: float
    gaussian_is_anomalous: bool
    latency_ms: float
    probabilities: Dict[str, float]


class InferenceEngine:
    """Bộ máy suy luận CNN-LSTM cho cả hai profile CIC-IDS2017 và CIC-DDoS2019."""

    def __init__(self, registry: Optional[ModelRegistry] = None) -> None:
        self._registry = registry or model_registry

    def predict_single_flow(
        self,
        flow: Union[Mapping[str, Any], np.ndarray],
        profile_id: str = "CIC-IDS2017",
        already_scaled: bool = False,
    ) -> InferencePrediction:
        """Suy luận cho một network flow đơn lẻ (dành cho profile CIC-IDS2017)."""
        if isinstance(flow, np.ndarray):
            batch_input = flow.reshape(1, -1) if flow.ndim == 1 else flow
        else:
            batch_input = [flow]
        results = self.predict_single_flow_batch(
            flows=batch_input, profile_id=profile_id, already_scaled=already_scaled
        )
        return results[0]

    def predict_single_flow_batch(
        self,
        flows: Union[Sequence[Mapping[str, Any]], np.ndarray],
        profile_id: str = "CIC-IDS2017",
        already_scaled: bool = False,
    ) -> List[InferencePrediction]:
        """Suy luận theo batch cho các network flow đơn lẻ (CIC-IDS2017)."""
        profile = self._registry.get_profile(profile_id)
        if profile.window_size != 1:
            raise ValueError(
                f"Profile {profile.profile_id} requires temporal window of {profile.window_size} flows"
            )

        t0 = perf_counter()
        scaled_matrix, tensor = preprocess_single_flow_batch(
            profile, flows, already_scaled=already_scaled
        )
        gaussian_results = compute_gaussian_scores(profile, scaled_matrix)
        predictions = self._forward_and_decode(profile, tensor, gaussian_results, t0)
        return predictions

    def predict_temporal_window(
        self,
        window_flows: Union[Sequence[Mapping[str, Any]], np.ndarray],
        profile_id: str = "CIC-DDoS2019",
        already_scaled: bool = False,
    ) -> InferencePrediction:
        """Suy luận cho một cửa sổ thời gian 8 flows liên tiếp (dành cho CIC-DDoS2019)."""
        if isinstance(window_flows, np.ndarray):
            batch_input = (
                window_flows.reshape(1, profile_window_size(self._registry, profile_id), -1)
                if window_flows.ndim == 2
                else window_flows
            )
        else:
            batch_input = [window_flows]
        results = self.predict_temporal_window_batch(
            windows=batch_input, profile_id=profile_id, already_scaled=already_scaled
        )
        return results[0]

    def predict_temporal_window_batch(
        self,
        windows: Union[Sequence[Sequence[Mapping[str, Any]]], np.ndarray],
        profile_id: str = "CIC-DDoS2019",
        already_scaled: bool = False,
    ) -> List[InferencePrediction]:
        """Suy luận theo batch cho các cửa sổ thời gian 8 flows (CIC-DDoS2019)."""
        profile = self._registry.get_profile(profile_id)
        if profile.window_size <= 1:
            raise ValueError(
                f"Profile {profile.profile_id} is single-flow and does not use temporal windows"
            )

        t0 = perf_counter()
        scaled_windows, tensor = preprocess_temporal_window_batch(
            profile, windows, already_scaled=already_scaled
        )
        gaussian_results = compute_gaussian_scores(profile, scaled_windows)
        predictions = self._forward_and_decode(profile, tensor, gaussian_results, t0)
        return predictions

    def _forward_and_decode(
        self,
        profile: LoadedProfile,
        tensor: torch.Tensor,
        gaussian_results: Sequence[GaussianScoreResult],
        start_time: float,
    ) -> List[InferencePrediction]:
        """Thực thi forward pass trong torch.inference_mode() và giải mã kết quả."""
        with torch.inference_mode():
            logits: torch.Tensor = profile.model(tensor)
            probs: torch.Tensor = torch.softmax(logits, dim=1)
            max_scores, argmax_indices = torch.max(probs, dim=1)

        total_elapsed_ms = (perf_counter() - start_time) * 1000.0
        batch_size = int(tensor.shape[0])
        per_item_latency_ms = total_elapsed_ms / max(batch_size, 1)

        probs_np = probs.cpu().numpy()
        scores_np = max_scores.cpu().numpy()
        indices_np = argmax_indices.cpu().numpy()

        benign_id = profile.benign_id
        dataset_name = str(profile.config.get("dataset", profile.profile_id))

        results: List[InferencePrediction] = []
        for idx in range(batch_size):
            pred_id = int(indices_np[idx])
            pred_label = profile.label_mapping[pred_id]
            class_score = float(scores_np[idx])
            row_probs = probs_np[idx]

            benign_score = float(row_probs[benign_id])
            # Tổng xác suất Softmax của tất cả các lớp ATTACK
            attack_score = float(np.sum(np.delete(row_probs, benign_id)))
            detection_status = "BENIGN" if pred_id == benign_id else "ATTACK"

            g_res = gaussian_results[idx]
            prob_map = {
                profile.label_mapping[c_idx]: float(row_probs[c_idx])
                for c_idx in range(profile.n_classes)
            }

            results.append(
                InferencePrediction(
                    profile_id=profile.profile_id,
                    dataset=dataset_name,
                    predicted_class_id=pred_id,
                    predicted_label=pred_label,
                    detection_status=detection_status,
                    class_score=class_score,
                    attack_score=attack_score,
                    benign_score=benign_score,
                    gaussian_anomaly_score=g_res.anomaly_score,
                    gaussian_threshold=g_res.threshold,
                    gaussian_is_anomalous=g_res.is_anomalous,
                    latency_ms=per_item_latency_ms,
                    probabilities=prob_map,
                )
            )

        return results


def profile_window_size(registry: ModelRegistry, profile_id: str) -> int:
    return registry.get_profile(profile_id).window_size


# Singleton inference engine dùng chung
inference_engine = InferenceEngine(model_registry)
