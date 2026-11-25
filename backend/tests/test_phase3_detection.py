"""Unit tests for Phase 3: Detection Engine, Gaussian Auxiliary Rule, Beaconing, and NetworkX Graph."""

from __future__ import annotations

import pytest
from types import SimpleNamespace
from unittest.mock import Mock

from backend.app.analysis.beaconing import BeaconingDetector
from backend.app.analysis.graph_analysis import NetworkGraphAnalyzer
from backend.app.core.detection_engine import DetectionEngine
from backend.app.core.inference import InferenceEngine
from backend.app.core.model_registry import ModelRegistry
from backend.app.network.flow_extractor import CompletedFlow


@pytest.mark.parametrize(
    "primary_status, temporal_status, selected_model",
    [
        ("BENIGN", "ATTACK", "CIC-DDoS2019"),
        ("ATTACK", "BENIGN", "CIC-IDS2017"),
        ("ATTACK", "ATTACK", "CIC-IDS2017"),
        ("BENIGN", "BENIGN", "CIC-IDS2017"),
    ],
)
def test_auto_fusion(registry, primary_status, temporal_status, selected_model):
    def prediction(profile_id, status, label, score):
        return SimpleNamespace(
            profile_id=profile_id, detection_status=status,
            predicted_label=label if status == "ATTACK" else "BENIGN",
            class_score=score, attack_score=score if status == "ATTACK" else 1 - score,
            gaussian_anomaly_score=0.0, gaussian_threshold=1.0,
            gaussian_is_anomalous=False, latency_ms=1.0,
        )

    inference = Mock()
    inference.predict_single_flow.return_value = prediction(
        "CIC-IDS2017", primary_status, "PortScan", 0.60
    )
    inference.predict_temporal_window.return_value = prediction(
        "CIC-DDoS2019", temporal_status, "DrDoS_DNS", 0.99
    )
    callback = Mock()
    detector = DetectionEngine(registry=registry, engine=inference, on_detection=callback)
    detector.start_new_session("AUTO", reset_analytics=True)
    records = [
        detector.process_flow(CompletedFlow(
            flow_id=f"hybrid-{i}", src_ip="192.0.2.1", dst_ip="192.0.2.2",
            src_port=50000 + i, dst_port=443, protocol=6,
            start_time=1700000000.0 + i, end_time=1700000000.5 + i,
            timestamp_iso=f"2026-01-01T00:00:0{i}Z", packet_count=1,
            features={}, data_source="PCAP_REPLAY",
        ))
        for i in range(8)
    ]
    assert all(r.dataset_profile == "AUTO" for r in records)
    assert all(r.detection_status == primary_status for r in records[:7])
    assert [r.buffered_flows for r in records] == list(range(1, 9))
    assert records[-1].detection_status == (
        "ATTACK" if "ATTACK" in (primary_status, temporal_status) else "BENIGN"
    )
    assert records[-1].class_score == (0.99 if selected_model == "CIC-DDoS2019" else 0.60)
    assert records[-1].inference_latency_ms == 2.0
    assert f"Displayed scores and label: {selected_model}" in records[-1].note
    assert inference.predict_single_flow.call_count == 8
    assert inference.predict_temporal_window.call_count == 1
    assert callback.call_count == 8
    assert detector.get_runtime_metrics()["total_inferences"] == 8
    assert detector.get_graph_summary().total_flows_in_graph == 8
    detector.start_new_session("AUTO")
    assert detector.get_runtime_metrics()["buffered_ips"] == {}


@pytest.fixture(scope="module")
def registry() -> ModelRegistry:
    reg = ModelRegistry()
    reg.load_all_profiles()
    return reg


@pytest.fixture(scope="module")
def det_engine(registry: ModelRegistry) -> DetectionEngine:
    return DetectionEngine(registry=registry, engine=InferenceEngine(registry))


def test_beaconing_detector_identifies_periodic_and_ignores_irregular() -> None:
    detector = BeaconingDetector(min_connections=5, cov_threshold=0.20)

    # 1. Cặp IP có chu kỳ đều đặn ~10 giây (CV rất thấp) -> Suspected Beaconing
    base_ts = 1700000000.0
    for i in range(6):
        detector.record_connection(
            src_ip="192.168.1.25",
            dst_ip="198.51.100.99",
            timestamp=base_ts + i * 10.0,
            dst_port=443,
            protocol=6,
        )

    # 2. Cặp IP có khoảng cách ngẫu nhiên bất quy tắc -> Irregular
    irregular_offsets = [0.0, 1.5, 25.0, 27.0, 120.0, 310.0]
    for off in irregular_offsets:
        detector.record_connection(
            src_ip="192.168.1.25",
            dst_ip="203.0.113.5",
            timestamp=base_ts + off,
            dst_port=80,
            protocol=6,
        )

    suspected = detector.get_candidates(only_suspected=True)
    assert len(suspected) == 1
    cand = suspected[0]
    assert cand.source_ip == "192.168.1.25"
    assert cand.destination_ip == "198.51.100.99"
    assert cand.connection_count == 6
    assert cand.mean_interval == pytest.approx(10.0, rel=1e-3)
    assert cand.coefficient_of_variation == pytest.approx(0.0, abs=1e-4)
    assert cand.status == "SUSPECTED_BEACONING"
    assert cand.is_suspected is True


def test_networkx_graph_analyzer_hub_and_p2p() -> None:
    analyzer = NetworkGraphAnalyzer(max_nodes=50, retention_seconds=600.0)
    t0 = 1700000000.0

    # Tạo mô hình tập trung: nhiều IP kết nối tới 10.0.0.100
    for i in range(1, 7):
        analyzer.record_flow(
            src_ip=f"192.168.1.{i}",
            dst_ip="10.0.0.100",
            timestamp=t0 + i,
            is_attack=True,
            attack_label="DDoS",
            gaussian_anomaly_score=310.5,
        )

    summary = analyzer.analyze()
    assert summary.total_nodes == 7
    assert summary.total_edges == 6
    assert summary.total_flows_in_graph == 6
    assert summary.topology_pattern == "CENTRALIZED_HUB"
    assert len(summary.hub_nodes) >= 1
    assert summary.hub_nodes[0]["ip"] == "10.0.0.100"
    assert "CENTRALIZED_TARGET_OR_HUB" in summary.hub_nodes[0]["roles"]


def test_detection_engine_single_flow_and_temporal_buffering(
    registry: ModelRegistry, det_engine: DetectionEngine
) -> None:
    # 1. Kiểm tra CIC-IDS2017 (single_flow)
    p_ids = registry.get_profile("CIC-IDS2017")
    medians_ids = p_ids.preprocessor_bundle["imputer"].statistics_
    feat_ids = {name: float(medians_ids[i]) for i, name in enumerate(p_ids.feature_names)}

    det_engine.start_new_session(profile_id="CIC-IDS2017", reset_analytics=True)
    flow1 = CompletedFlow(
        flow_id="f-1",
        src_ip="192.168.1.15",
        dst_ip="10.0.0.20",
        src_port=54321,
        dst_port=80,
        protocol=6,
        start_time=1700000000.0,
        end_time=1700000001.0,
        timestamp_iso="2026-01-01T00:00:01Z",
        packet_count=5,
        features=feat_ids,
        data_source="CSV_REPLAY",
    )
    rec1 = det_engine.process_flow(flow1)
    assert rec1.dataset_profile == "CIC-IDS2017"
    assert rec1.detection_status in ("BENIGN", "ATTACK")
    assert rec1.buffered_flows == 1

    # 2. Kiểm tra CIC-DDoS2019 (7 flows đầu trả BUFFERING, flow thứ 8 trả BENIGN/ATTACK)
    p_ddos = registry.get_profile("CIC-DDoS2019")
    medians_ddos = p_ddos.preprocessor_bundle["imputer"].statistics_
    feat_ddos = {name: float(medians_ddos[i]) for i, name in enumerate(p_ddos.feature_names)}

    det_engine.start_new_session(profile_id="CIC-DDoS2019", reset_analytics=False)
    records = []
    for idx in range(8):
        fl = CompletedFlow(
            flow_id=f"ddos-{idx}",
            src_ip="172.16.0.99",
            dst_ip="10.0.0.1",
            src_port=40000 + idx,
            dst_port=53,
            protocol=17,
            start_time=1700000100.0 + idx * 1.0,
            end_time=1700000100.5 + idx * 1.0,
            timestamp_iso="2026-01-01T00:01:40Z",
            packet_count=2,
            features=feat_ddos,
            data_source="PCAP_REPLAY",
        )
        records.append(det_engine.process_flow(fl))

    for r in records[:7]:
        assert r.detection_status == "BUFFERING"
        assert r.predicted_attack_type == "BUFFERING"

    final_rec = records[7]
    assert final_rec.detection_status in ("BENIGN", "ATTACK")
    assert final_rec.predicted_attack_type in p_ddos.class_names
    assert final_rec.buffered_flows == 8
