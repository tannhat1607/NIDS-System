"""Loader for offline evaluation metrics and comparison tables directly from Colab artifacts.

Đọc trực tiếp kết quả huấn luyện & đánh giá đã export từ Google Colab:
- CIC-IDS2017:
  + test_metrics.json
  + classification_report.csv
  + confusion_matrix.csv
  + model_comparison.csv
  + training_history.csv
- CIC-DDoS2019 (NIDS_Model_v1):
  + test_metrics.csv
  + classification_report.csv
  + confusion_matrix.csv
  + pipeline_comparison.csv
  + validation_comparison.csv

Nguyên tắc bắt buộc (Mục 11 - Trang 5):
- Không chạy lại huấn luyện hoặc thực nghiệm để tạo dữ liệu cho trang này.
- Phân biệt rõ Binary Accuracy (99.69%) và Multiclass 17-class Accuracy (55.36%) của CIC-DDoS2019.
- Không hiển thị 99.69% của CIC-DDoS2019 như độ chính xác phân loại 17 lớp hoặc độ chính xác realtime.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pandas as pd

from backend.app.config import get_profile_specs


def load_all_model_performance() -> Dict[str, Any]:
    """Đọc toàn bộ chỉ số đánh giá từ thư mục artifact của cả hai profile."""
    specs = get_profile_specs()
    return {
        "CIC-IDS2017": _load_cic_ids2017_performance(specs["CIC-IDS2017"].artifact_dir),
        "CIC-DDoS2019": _load_cic_ddos2019_performance(specs["CIC-DDoS2019"].artifact_dir),
    }


def _parse_confusion_matrix(csv_path: Any) -> Dict[str, Any]:
    df = pd.read_csv(csv_path, index_col=0)
    labels = [str(c) for c in df.columns]
    matrix = [[int(val) for val in row] for row in df.to_numpy()]
    return {"labels": labels, "matrix": matrix}


def _load_cic_ids2017_performance(artifact_dir: Any) -> Dict[str, Any]:
    config = json.loads((artifact_dir / "config.json").read_text(encoding="utf-8"))
    metrics_json = json.loads((artifact_dir / "test_metrics.json").read_text(encoding="utf-8"))

    report_df = pd.read_csv(artifact_dir / "classification_report.csv", index_col=0)
    per_class: List[Dict[str, Any]] = []
    macro_precision = 0.0
    macro_recall = 0.0
    macro_f1 = float(metrics_json.get("Test_Macro_F1", 0.0))

    for class_label, row in report_df.iterrows():
        label_str = str(class_label).strip()
        if label_str == "macro avg":
            macro_precision = float(row.get("precision", 0.0))
            macro_recall = float(row.get("recall", 0.0))
            macro_f1 = float(row.get("f1-score", macro_f1))
            continue
        if label_str in ("accuracy", "weighted avg"):
            continue
        per_class.append(
            {
                "class_name": label_str,
                "precision": round(float(row.get("precision", 0.0)), 4),
                "recall": round(float(row.get("recall", 0.0)), 4),
                "f1_score": round(float(row.get("f1-score", 0.0)), 4),
                "support": int(float(row.get("support", 0))),
            }
        )

    cm = _parse_confusion_matrix(artifact_dir / "confusion_matrix.csv")

    # Tính Binary FPR từ confusion matrix (hàng BENIGN bị dự đoán nhầm sang các lớp Attack)
    benign_idx = cm["labels"].index("BENIGN") if "BENIGN" in cm["labels"] else 0
    benign_row = cm["matrix"][benign_idx]
    tn = benign_row[benign_idx]
    fp = sum(benign_row) - tn
    fpr = fp / max(1, tn + fp)

    model_comp_path = artifact_dir / "model_comparison.csv"
    model_comparison: List[Dict[str, Any]] = []
    if model_comp_path.exists():
        comp_df = pd.read_csv(model_comp_path)
        for _, r in comp_df.iterrows():
            model_comparison.append(
                {
                    "model": str(r.get("Model", "")),
                    "val_macro_f1": round(float(r.get("Val_Macro_F1", 0.0)), 4),
                    "test_macro_f1": round(float(r.get("Test_Macro_F1", 0.0)), 4),
                    "test_accuracy": round(float(r.get("Test_Accuracy", 0.0)), 4),
                    "test_balanced_accuracy": round(
                        float(r.get("Test_Balanced_Accuracy", 0.0)), 4
                    ),
                    "best_epoch": int(r.get("Best_Epoch", 0)),
                }
            )

    history_path = artifact_dir / "training_history.csv"
    training_history: List[Dict[str, Any]] = []
    if history_path.exists():
        hist_df = pd.read_csv(history_path)
        for _, r in hist_df.iterrows():
            training_history.append(
                {
                    "epoch": int(r.get("Epoch", 0)),
                    "train_loss": round(float(r.get("Train_Loss", 0.0)), 4),
                    "val_macro_f1": round(float(r.get("Val_Macro_F1", 0.0)), 4),
                }
            )

    return {
        "profile_id": "CIC-IDS2017",
        "dataset": config.get("dataset", "CIC-IDS2017"),
        "model_name": config.get("model", "FlowFeatureCNNLSTM"),
        "architecture": "Feature-sequence CNN-LSTM",
        "input_shape": [70],
        "n_features": 70,
        "n_classes": 12,
        "window_size": 1,
        "stride": 1,
        "best_epoch": int(metrics_json.get("Best_Epoch", config.get("best_epoch", 7))),
        "gaussian_threshold": round(float(config.get("gaussian_threshold", 263.7635)), 4),
        "evaluation_note": (
            "Đánh giá offline trên tập Test CIC-IDS2017 (7,580 flows, 12 lớp phân loại từng flow)."
        ),
        "multiclass_metrics": {
            "accuracy": round(float(metrics_json.get("Test_Accuracy", 0.944855)), 6),
            "balanced_accuracy": round(
                float(metrics_json.get("Test_Balanced_Accuracy", 0.893863)), 6
            ),
            "macro_precision": round(macro_precision, 6),
            "macro_recall": round(macro_recall, 6),
            "macro_f1": round(macro_f1, 6),
            "val_macro_f1": round(float(metrics_json.get("Val_Macro_F1", 0.862683)), 6),
            "false_positive_rate": round(float(fpr), 6),
        },
        "binary_metrics": None,
        "per_class": per_class,
        "confusion_matrix": cm,
        "model_comparison": model_comparison,
        "pipeline_comparison": [],
        "training_history": training_history,
    }


def _load_cic_ddos2019_performance(artifact_dir: Any) -> Dict[str, Any]:
    config = json.loads((artifact_dir / "config.json").read_text(encoding="utf-8"))
    tm_df = pd.read_csv(artifact_dir / "test_metrics.csv")
    tm_row = tm_df.iloc[0]

    report_df = pd.read_csv(artifact_dir / "classification_report.csv")
    per_class: List[Dict[str, Any]] = []
    for _, row in report_df.iterrows():
        per_class.append(
            {
                "class_name": str(row.get("Class", "")).strip(),
                "precision": round(float(row.get("Precision", 0.0)), 4),
                "recall": round(float(row.get("Recall", 0.0)), 4),
                "f1_score": round(float(row.get("F1", 0.0)), 4),
                "support": int(float(row.get("Support", 0))),
            }
        )

    cm = _parse_confusion_matrix(artifact_dir / "confusion_matrix.csv")

    val_comp_path = artifact_dir / "validation_comparison.csv"
    model_comparison: List[Dict[str, Any]] = []
    if val_comp_path.exists():
        vc_df = pd.read_csv(val_comp_path)
        for _, r in vc_df.iterrows():
            model_comparison.append(
                {
                    "model": str(r.get("Model", "")),
                    "multiclass_accuracy": round(float(r.get("Accuracy", 0.0)), 4),
                    "macro_precision": round(float(r.get("Precision_Macro", 0.0)), 4),
                    "macro_recall": round(float(r.get("Recall_Macro", 0.0)), 4),
                    "macro_f1": round(float(r.get("Macro_F1", 0.0)), 4),
                    "binary_accuracy": round(float(r.get("Binary_Accuracy", 0.0)), 4),
                    "binary_f1": round(float(r.get("Binary_F1", 0.0)), 4),
                    "fpr": round(float(r.get("FPR", 0.0)), 4),
                    "latency_p50_ms": round(float(r.get("Latency_P50_ms", 0.0)), 4),
                    "latency_p95_ms": round(float(r.get("Latency_P95_ms", 0.0)), 4),
                    "parameters": int(r.get("Parameters", 0)),
                }
            )

    pipe_comp_path = artifact_dir / "pipeline_comparison.csv"
    pipeline_comparison: List[Dict[str, Any]] = []
    if pipe_comp_path.exists():
        pc_df = pd.read_csv(pipe_comp_path)
        for _, r in pc_df.iterrows():
            pipeline_comparison.append(
                {
                    "pipeline": str(r.get("Pipeline", "")),
                    "binary_accuracy": round(float(r.get("Accuracy", 0.0)), 4),
                    "attack_precision": round(float(r.get("Precision", 0.0)), 4),
                    "attack_recall": round(float(r.get("Recall", 0.0)), 4),
                    "binary_f1": round(float(r.get("F1", 0.0)), 4),
                    "fpr": round(float(r.get("FPR", 0.0)), 4),
                    "tp": int(r.get("TP", 0)),
                    "tn": int(r.get("TN", 0)),
                    "fp": int(r.get("FP", 0)),
                    "fn": int(r.get("FN", 0)),
                }
            )

    return {
        "profile_id": "CIC-DDoS2019",
        "dataset": config.get("dataset", "CIC-DDoS2019_v2"),
        "model_name": config.get("model", "TemporalCNNLSTM"),
        "architecture": "Temporal CNN-LSTM (8-flow sequence)",
        "input_shape": [8, 66],
        "n_features": 66,
        "n_classes": 17,
        "window_size": int(config.get("window_size", 8)),
        "stride": int(config.get("stride", 8)),
        "best_epoch": int(config.get("best_epoch", 22)),
        "gaussian_threshold": round(float(config.get("gaussian_threshold", 185.0203)), 4),
        "evaluation_note": (
            "Đánh giá offline trên tập Test CIC-DDoS2019 V2 (15,736 cửa sổ 8-flow). "
            "Lưu ý: Binary Accuracy (99.69%) là độ chính xác phân biệt BENIGN vs ATTACK (nhị phân) "
            "trên tập Test offline; Multiclass 17-class Accuracy đạt 55.36% (Macro-F1 52.43%) do sự tương đồng "
            "đặc trưng giữa các họ giao thức phản xạ UDP/DrDoS."
        ),
        "multiclass_metrics": {
            "accuracy": round(float(tm_row.get("Accuracy", 0.553635)), 6),
            "macro_precision": round(float(tm_row.get("Precision_Macro", 0.519008)), 6),
            "macro_recall": round(float(tm_row.get("Recall_Macro", 0.550939)), 6),
            "macro_f1": round(float(tm_row.get("Macro_F1", 0.524262)), 6),
        },
        "binary_metrics": {
            "binary_accuracy": round(float(tm_row.get("Binary_Accuracy", 0.996886)), 6),
            "attack_precision": round(float(tm_row.get("Attack_Precision", 0.998609)), 6),
            "attack_recall": round(float(tm_row.get("Attack_Recall", 0.998146)), 6),
            "binary_f1": round(float(tm_row.get("Binary_F1", 0.998378)), 6),
            "false_positive_rate": round(float(tm_row.get("FPR", 0.033281)), 6),
            "tp": int(tm_row.get("TP", 15077)),
            "tn": int(tm_row.get("TN", 610)),
            "fp": int(tm_row.get("FP", 21)),
            "fn": int(tm_row.get("FN", 28)),
        },
        "per_class": per_class,
        "confusion_matrix": cm,
        "model_comparison": model_comparison,
        "pipeline_comparison": pipeline_comparison,
        "training_history": [],
    }
