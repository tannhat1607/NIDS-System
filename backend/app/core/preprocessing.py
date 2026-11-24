"""Preprocessing pipeline aligned with Google Colab training artifacts.

Đảm bảo tuân thủ tuyệt đối pipeline tiền xử lý khi huấn luyện trên Colab:
1. Kiểm tra và sắp xếp đúng thứ tự đặc trưng theo feature_names của từng profile.
2. Phân biệt rõ đặc trưng bị thiếu giá trị hợp lệ (NaN/Inf -> được xử lý bởi SimpleImputer)
   với đặc trưng bị thiếu cột (Unimplemented/Missing feature key -> báo lỗi, tuyệt đối không tự điền 0).
3. Với CIC-IDS2017: ép kiểu số, thay thế +-Inf bằng NaN, clip [-1e12, 1e12],
   áp dụng imputer.transform() và scaler.transform() -> float32 tensor shape (Batch, 70).
4. Với CIC-DDoS2019: ép kiểu số cho chuỗi 8 flows, thay thế +-Inf bằng NaN,
   áp dụng imputer.transform() và scaler.transform() trên ma trận phẳng (-1, 66),
   sau đó reshape lại thành float32 tensor shape (Batch, 8, 66).
5. Tuyệt đối không fit lại imputer/scaler và không chuẩn hóa hai lần.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Union

import numpy as np
import pandas as pd
import torch

from backend.app.core.model_registry import LoadedProfile


class FeatureCompatibilityError(ValueError):
    """Ngoại lệ khi thiếu đặc trưng bắt buộc trong dữ liệu đầu vào."""


# Ánh xạ các biến thể tên cột thường gặp trong CICFlowMeter / CSV gốc sang tên chuẩn của model
FEATURE_ALIASES: Dict[str, List[str]] = {
    "Total Backward Packets": ["Total Bwd packets", "Total Backward Packets"],
    "Total Length of Fwd Packets": ["Total Length of Fwd Packet", "Total Length of Fwd Packets"],
    "Total Length of Bwd Packets": ["Total Length of Bwd Packet", "Total Length of Bwd Packets"],
    "Fwd Header Length": ["Fwd Header Length", "Fwd Header Len"],
    "Bwd Header Length": ["Bwd Header Length", "Bwd Header Len"],
    "CWE Flag Count": ["CWE Flag Count", "CWR Flag Count"],
    "Avg Fwd Segment Size": ["Avg Fwd Segment Size", "Fwd Segment Size Avg"],
    "Avg Bwd Segment Size": ["Avg Bwd Segment Size", "Bwd Segment Size Avg"],
    "Init_Win_bytes_forward": ["Init_Win_bytes_forward", "FWD Init Win Bytes"],
    "Init_Win_bytes_backward": ["Init_Win_bytes_backward", "Bwd Init Win Bytes"],
    "act_data_pkt_fwd": ["act_data_pkt_fwd", "Fwd Act Data Pkts"],
    "min_seg_size_forward": ["min_seg_size_forward", "Fwd Seg Size Min"],
}


def canonicalize_feature_dict(
    raw_record: Mapping[str, Any], expected_features: Sequence[str]
) -> Dict[str, Any]:
    """Chuẩn hóa key của dictionary dữ liệu flow về đúng tên đặc trưng mà model yêu cầu.

    Không tự động điền 0 cho các đặc trưng chưa được cung cấp. Nếu thiếu bất kỳ
    đặc trưng nào trong expected_features, ném lỗi FeatureCompatibilityError.
    """
    stripped_map: Dict[str, Any] = {str(k).strip(): v for k, v in raw_record.items()}
    lower_map: Dict[str, Any] = {k.lower(): v for k, v in stripped_map.items()}

    ordered_record: Dict[str, Any] = {}
    missing_features: List[str] = []

    for feat in expected_features:
        if feat in stripped_map:
            ordered_record[feat] = stripped_map[feat]
            continue

        # Kiểm tra không phân biệt hoa thường
        feat_lower = feat.lower()
        if feat_lower in lower_map:
            ordered_record[feat] = lower_map[feat_lower]
            continue

        # Kiểm tra trong danh sách alias hợp lệ của CICFlowMeter
        matched = False
        for alias in FEATURE_ALIASES.get(feat, []):
            if alias in stripped_map:
                ordered_record[feat] = stripped_map[alias]
                matched = True
                break
            if alias.lower() in lower_map:
                ordered_record[feat] = lower_map[alias.lower()]
                matched = True
                break

        if not matched:
            missing_features.append(feat)

    if missing_features:
        raise FeatureCompatibilityError(
            f"Missing {len(missing_features)} required feature(s): {missing_features[:10]}"
        )

    return ordered_record


def _coerce_numeric_matrix(
    records: Sequence[Mapping[str, Any]],
    feature_names: Sequence[str],
    clip_extremes: bool,
) -> np.ndarray:
    """Chuyển danh sách dict đặc trưng thành ma trận float32 (N, F) đúng thứ tự."""
    rows: List[List[float]] = []
    for rec in records:
        canonical = canonicalize_feature_dict(rec, feature_names)
        row_vals: List[float] = []
        for feat in feature_names:
            val = canonical[feat]
            if val is None or val == "" or (isinstance(val, str) and val.strip().lower() in ("nan", "inf", "-inf", "infinity", "-infinity")):
                num = np.nan
            else:
                try:
                    num = float(val)
                except (TypeError, ValueError):
                    num = np.nan
            if not np.isfinite(num):
                num = np.nan
            elif clip_extremes:
                # Trong Cell 14 (CIC-IDS2017), giá trị được clip trong [-1e12, 1e12]
                if num > 1e12:
                    num = 1e12
                elif num < -1e12:
                    num = -1e12
            row_vals.append(num)
        rows.append(row_vals)

    return np.asarray(rows, dtype=np.float32)


def preprocess_single_flow_batch(
    profile: LoadedProfile,
    flows: Union[Sequence[Mapping[str, Any]], pd.DataFrame, np.ndarray],
    already_scaled: bool = False,
) -> tuple[np.ndarray, torch.Tensor]:
    """Tiền xử lý batch các flow đơn lẻ cho profile CIC-IDS2017 (Batch, 70).

    Trả về:
        - scaled_matrix: np.ndarray shape (Batch, 70) kiểu float32 (dùng cho cả Gaussian).
        - tensor: torch.Tensor shape (Batch, 70) kiểu float32 trên CPU.
    """
    if profile.window_size != 1:
        raise ValueError(
            f"preprocess_single_flow_batch only supports window_size=1, got {profile.window_size}"
        )

    feature_names = profile.feature_names
    n_features = profile.n_features

    if already_scaled:
        if isinstance(flows, np.ndarray):
            arr = flows.astype(np.float32, copy=False)
        else:
            raise TypeError("already_scaled=True requires a numpy.ndarray input")
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != n_features:
            raise ValueError(f"Expected shape (Batch, {n_features}), got {arr.shape}")
        if not np.isfinite(arr).all():
            raise ValueError("Pre-scaled input contains NaN or Inf")
        return arr, torch.from_numpy(arr)

    if isinstance(flows, pd.DataFrame):
        records = flows.to_dict(orient="records")
        raw_matrix = _coerce_numeric_matrix(records, feature_names, clip_extremes=True)
    elif isinstance(flows, np.ndarray):
        arr = flows.astype(np.float32, copy=True)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != n_features:
            raise ValueError(f"Expected {n_features} features, got {arr.shape[1]}")
        arr[~np.isfinite(arr)] = np.nan
        arr = np.clip(arr, -1e12, 1e12)
        raw_matrix = arr
    else:
        if len(flows) == 0:
            raise ValueError("Empty flows sequence provided for preprocessing")
        raw_matrix = _coerce_numeric_matrix(flows, feature_names, clip_extremes=True)

    imputer = profile.preprocessor_bundle["imputer"]
    scaler = profile.preprocessor_bundle["scaler"]

    # Chỉ sử dụng transform(), tuyệt đối không fit lại
    imputed = imputer.transform(raw_matrix)
    scaled = scaler.transform(imputed).astype(np.float32)

    if not np.isfinite(scaled).all():
        raise ValueError("Scaled feature matrix still contains NaN or Inf after transformation")

    tensor = torch.from_numpy(scaled)
    return scaled, tensor


def preprocess_temporal_window_batch(
    profile: LoadedProfile,
    windows: Union[Sequence[Sequence[Mapping[str, Any]]], np.ndarray],
    already_scaled: bool = False,
) -> tuple[np.ndarray, torch.Tensor]:
    """Tiền xử lý batch các cửa sổ 8 flows cho profile CIC-DDoS2019 (Batch, 8, 66).

    Trả về:
        - scaled_windows: np.ndarray shape (Batch, 8, 66) kiểu float32.
        - tensor: torch.Tensor shape (Batch, 8, 66) kiểu float32 trên CPU.
    """
    window_size = profile.window_size
    n_features = profile.n_features
    feature_names = profile.feature_names

    if already_scaled:
        if not isinstance(windows, np.ndarray):
            raise TypeError("already_scaled=True requires a numpy.ndarray input")
        arr = windows.astype(np.float32, copy=False)
        if arr.ndim == 2 and arr.shape == (window_size, n_features):
            arr = arr.reshape(1, window_size, n_features)
        if arr.ndim != 3 or arr.shape[1:] != (window_size, n_features):
            raise ValueError(
                f"Expected shape (Batch, {window_size}, {n_features}), got {arr.shape}"
            )
        if not np.isfinite(arr).all():
            raise ValueError("Pre-scaled temporal window contains NaN or Inf")
        return arr, torch.from_numpy(arr)

    if isinstance(windows, np.ndarray):
        arr = windows.astype(np.float32, copy=True)
        if arr.ndim == 2 and arr.shape == (window_size, n_features):
            arr = arr.reshape(1, window_size, n_features)
        if arr.ndim != 3 or arr.shape[1:] != (window_size, n_features):
            raise ValueError(
                f"Expected shape (Batch, {window_size}, {n_features}), got {arr.shape}"
            )
        arr[~np.isfinite(arr)] = np.nan
        raw_windows = arr
    else:
        if len(windows) == 0:
            raise ValueError("Empty windows sequence provided for temporal preprocessing")
        window_matrices: List[np.ndarray] = []
        for win in windows:
            if len(win) != window_size:
                raise ValueError(
                    f"Temporal window must contain exactly {window_size} flows, got {len(win)}"
                )
            # Trong Cell 30 & 30.2 (CIC-DDoS2019_v2), features[~np.isfinite(features)] = np.nan
            mat = _coerce_numeric_matrix(win, feature_names, clip_extremes=False)
            window_matrices.append(mat)
        raw_windows = np.stack(window_matrices, axis=0).astype(np.float32)

    batch_size = raw_windows.shape[0]
    flat = raw_windows.reshape(-1, n_features)

    imputer = profile.preprocessor_bundle["imputer"]
    scaler = profile.preprocessor_bundle["scaler"]

    # Transform phẳng (-1, 66) rồi reshape về (Batch, 8, 66) đúng y hệt Cell 30.2
    transformed_flat = scaler.transform(imputer.transform(flat))
    scaled_windows = transformed_flat.reshape(batch_size, window_size, n_features).astype(
        np.float32
    )

    if not np.isfinite(scaled_windows).all():
        raise ValueError("Scaled temporal window still contains NaN or Inf after transformation")

    tensor = torch.from_numpy(scaled_windows)
    return scaled_windows, tensor
