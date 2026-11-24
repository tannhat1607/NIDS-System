"""Phase 6 AI & End-to-End Benchmark Tests: P50/P95 Latency, Output Shape, Label & Coverage."""

from __future__ import annotations

from pathlib import Path
from time import perf_counter

import numpy as np
import pytest

from backend.app.core.detection_engine import DetectionEngine
from backend.app.core.inference import InferenceEngine
from backend.app.core.model_registry import ModelRegistry
from backend.app.network.packet_capture import iter_csv_flows, read_pcap_flows
from backend.app.network.sample_generator import ensure_sample_replay_files


@pytest.fixture(scope="module")
def registry() -> ModelRegistry:
    reg = ModelRegistry()
    reg.load_all_profiles()
    return reg


@pytest.fixture(scope="module")
def engine(registry: ModelRegistry) -> InferenceEngine:
    return InferenceEngine(registry)


def test_ai_inference_latency_p50_and_p95_both_profiles(
    registry: ModelRegistry, engine: InferenceEngine
) -> None:
    """Đo inference latency P50 và P95 trên CPU cho cả 2 profile CNN-LSTM."""
    # 1. CIC-IDS2017 (Single Flow, 70 features)
    p_ids = registry.get_profile("CIC-IDS2017")
    medians_ids = p_ids.preprocessor_bundle["imputer"].statistics_
    flow_ids = {feat: float(medians_ids[i]) for i, feat in enumerate(p_ids.feature_names)}

    # Warm-up
    for _ in range(3):
        engine.predict_single_flow(flow_ids, profile_id="CIC-IDS2017")

    latencies_ids = []
    for _ in range(50):
        pred = engine.predict_single_flow(flow_ids, profile_id="CIC-IDS2017")
        latencies_ids.append(pred.latency_ms)

    p50_ids = float(np.percentile(latencies_ids, 50))
    p95_ids = float(np.percentile(latencies_ids, 95))
    assert p50_ids < 100.0
    assert p95_ids < 200.0

    # 2. CIC-DDoS2019 (Temporal Window 8 flows, 66 features)
    p_ddos = registry.get_profile("CIC-DDoS2019")
    medians_ddos = p_ddos.preprocessor_bundle["imputer"].statistics_
    flow_ddos = {feat: float(medians_ddos[i]) for i, feat in enumerate(p_ddos.feature_names)}
    window_ddos = [dict(flow_ddos) for _ in range(8)]

    for _ in range(3):
        engine.predict_temporal_window(window_ddos, profile_id="CIC-DDoS2019")

    latencies_ddos = []
    for _ in range(50):
        pred = engine.predict_temporal_window(window_ddos, profile_id="CIC-DDoS2019")
        latencies_ddos.append(pred.latency_ms)

    p50_ddos = float(np.percentile(latencies_ddos, 50))
    p95_ddos = float(np.percentile(latencies_ddos, 95))
    assert p50_ddos < 100.0
    assert p95_ddos < 200.0


def test_end_to_end_csv_and_pcap_coverage_reporting(registry: ModelRegistry) -> None:
    """Kiểm tra tỷ lệ coverage khi chạy CSV Replay và PCAP Replay (bao gồm báo cáo rõ số lượng BUFFERING)."""
    samples = ensure_sample_replay_files()
    det = DetectionEngine(registry=registry, engine=InferenceEngine(registry))

    # 1. PCAP Replay trên CIC-IDS2017 -> 100% flow được inference (window_size = 1)
    det.start_new_session(profile_id="CIC-IDS2017", reset_analytics=True)
    t0 = perf_counter()
    pcap_flows, pkt_count = read_pcap_flows(Path(samples["sample_pcap"]))
    for fl in pcap_flows:
        det.process_flow(fl, profile_id="CIC-IDS2017")
    e2e_ms_ids = (perf_counter() - t0) * 1000.0

    metrics_ids = det.get_runtime_metrics()
    assert pkt_count == 40
    assert metrics_ids["total_flows_seen"] == 16
    assert metrics_ids["total_inferences"] == 16
    assert metrics_ids["total_buffering"] == 0
    assert metrics_ids["inference_coverage_ratio"] == 1.0
    assert e2e_ms_ids > 0.0

    # 2. CSV Replay trên CIC-DDoS2019 -> 24 flows (3 nhóm 8-flow) -> 3 inferences, 21 BUFFERING
    p_ddos = registry.get_profile("CIC-DDoS2019")
    det.start_new_session(profile_id="CIC-DDoS2019", reset_analytics=True)
    csv_flows = list(
        iter_csv_flows(Path(samples["cic_ddos2019_csv"]), expected_features=p_ddos.feature_names)
    )
    for fl in csv_flows:
        det.process_flow(fl, profile_id="CIC-DDoS2019")

    metrics_ddos = det.get_runtime_metrics()
    assert metrics_ddos["total_flows_seen"] == 24
    assert metrics_ddos["total_inferences"] == 3
    assert metrics_ddos["total_buffering"] == 21
    # Coverage = 3 cửa sổ (tương ứng 24/24 flows đã đi vào 3 cửa sổ hoàn chỉnh, tỷ lệ inference/flow = 3/24 = 0.125)
    assert metrics_ddos["inference_coverage_ratio"] == pytest.approx(3 / 24, rel=1e-4)
