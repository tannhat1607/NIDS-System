"""Integration tests for Phase 4: FastAPI REST endpoints, WebSocket, and SQLite persistence."""

from __future__ import annotations

import pytest

from backend.app.api.monitoring_service import monitoring_service, ws_hub
from backend.app.api.schemas import (
    DirectInferenceRequest,
    ProfileSelectRequest,
)
from backend.app.core.model_registry import model_registry
from backend.app.main import (
    direct_ai_inference,
    export_alerts_csv,
    get_alert_detail,
    get_attack_statistics,
    get_beaconing_analysis,
    get_health,
    get_interfaces,
    get_model_performance,
    get_monitoring_status,
    get_network_graph,
    get_profiles,
    get_traffic_statistics,
    list_alerts,
    run_builtin_sample_replay,
    select_profile,
)
from backend.app.network.sample_generator import ensure_sample_replay_files


@pytest.fixture(scope="module", autouse=True)
def setup_app_state() -> None:
    model_registry.load_all_profiles()
    ensure_sample_replay_files()


def test_health_and_profiles_endpoints() -> None:
    h_data = get_health()
    assert h_data["status"] == "healthy"
    assert "CIC-IDS2017" in h_data["loaded_profiles"]
    assert "CIC-DDoS2019" in h_data["loaded_profiles"]

    p_data = get_profiles()
    assert len(p_data["profiles"]) == 2
    assert "AUTO" in p_data["detection_modes"]

    ifaces = get_interfaces()
    assert len(ifaces["interfaces"]) >= 1


def test_auto_sample_pcap_replay() -> None:
    assert select_profile(ProfileSelectRequest(profile_id="AUTO"))["active_profile"] == "AUTO"
    result = run_builtin_sample_replay(profile_id="AUTO", data_source="PCAP_REPLAY")
    assert result["flows_processed"] >= 8
    assert result["inferences_completed"] == result["flows_processed"]
    assert result["buffering_count"] == 0
    assert all(record["dataset_profile"] == "AUTO" for record in result["records"])
    assert any(record["buffered_flows"] == 8 for record in result["records"])
    detail = get_alert_detail(result["records"][-1]["alert_id"])
    assert detail["note"] == result["records"][-1]["note"]
    with pytest.raises(ValueError, match="AUTO requires"):
        monitoring_service.start_monitoring("AUTO", "CSV_REPLAY")


def test_switch_profile_and_direct_inference() -> None:
    sel_data = select_profile(ProfileSelectRequest(profile_id="CIC-IDS2017"))
    assert sel_data["active_profile"] == "CIC-IDS2017"

    p_ids = model_registry.get_profile("CIC-IDS2017")
    medians_ids = p_ids.preprocessor_bundle["imputer"].statistics_
    feat_ids = {name: float(medians_ids[i]) for i, name in enumerate(p_ids.feature_names)}

    inf_data = direct_ai_inference(
        DirectInferenceRequest(
            profile_id="CIC-IDS2017",
            source_ip="192.168.100.10",
            destination_ip="10.0.0.80",
            source_port=55111,
            destination_port=80,
            protocol=6,
            features=feat_ids,
        )
    )
    assert inf_data["dataset_profile"] == "CIC-IDS2017"
    assert inf_data["detection_status"] in ("BENIGN", "ATTACK")

    sel2_data = select_profile(ProfileSelectRequest(profile_id="CIC-DDoS2019"))
    assert sel2_data["active_profile"] == "CIC-DDoS2019"

    p_ddos = model_registry.get_profile("CIC-DDoS2019")
    medians_ddos = p_ddos.preprocessor_bundle["imputer"].statistics_
    feat_ddos = {name: float(medians_ddos[i]) for i, name in enumerate(p_ddos.feature_names)}

    inf2_data = direct_ai_inference(
        DirectInferenceRequest(
            profile_id="CIC-DDoS2019",
            source_ip="172.16.1.99",
            destination_ip="10.0.0.53",
            source_port=49000,
            destination_port=53,
            protocol=17,
            window_features=[feat_ddos for _ in range(8)],
        )
    )
    assert inf2_data["dataset_profile"] == "CIC-DDoS2019"
    assert inf2_data["detection_status"] in ("BENIGN", "ATTACK")
    assert inf2_data["buffered_flows"] == 8

    select_profile(ProfileSelectRequest(profile_id="CIC-IDS2017"))


def test_sample_replay_alerts_stats_and_csv_export() -> None:
    rep1 = run_builtin_sample_replay(profile_id="CIC-IDS2017", data_source="CSV_REPLAY")
    assert rep1["flows_processed"] == 24

    rep2 = run_builtin_sample_replay(profile_id="CIC-DDoS2019", data_source="CSV_REPLAY")
    assert rep2["flows_processed"] == 24
    assert rep2["inferences_completed"] == 3
    assert rep2["buffering_count"] == 21

    alerts_data = list_alerts(
        page=1,
        page_size=10,
        detection_status=None,
        dataset_profile=None,
        attack_type=None,
        ip=None,
        data_source=None,
        start_time=None,
        end_time=None,
        search=None,
    )
    assert alerts_data["total"] >= 10
    first_alert_id = alerts_data["items"][0]["alert_id"]

    detail = get_alert_detail(first_alert_id)
    assert detail["alert_id"] == first_alert_id

    csv_resp = export_alerts_csv(
        detection_status=None,
        dataset_profile=None,
        attack_type=None,
        ip=None,
    )
    assert "alert_id,detected_at" in csv_resp.body.decode("utf-8")

    traffic = get_traffic_statistics(dataset_profile=None)
    assert traffic["total_inferences"] >= 10

    attacks = get_attack_statistics(dataset_profile=None)
    assert "distribution" in attacks

    beaconing = get_beaconing_analysis(only_suspected=False)
    assert "candidates" in beaconing

    graph = get_network_graph()
    assert graph["total_nodes"] >= 2

    perf = get_model_performance()
    assert perf["CIC-IDS2017"]["multiclass_metrics"]["accuracy"] == pytest.approx(
        0.944855, rel=1e-4
    )
    assert perf["CIC-DDoS2019"]["multiclass_metrics"]["accuracy"] == pytest.approx(
        0.553635, rel=1e-4
    )
    assert perf["CIC-DDoS2019"]["binary_metrics"]["binary_accuracy"] == pytest.approx(
        0.996886, rel=1e-4
    )


def test_monitoring_status_and_ws_hub() -> None:
    st = get_monitoring_status()
    assert "is_monitoring" in st
    assert "active_profile" in st
    ws_hub.broadcast_from_thread({"type": "STATUS_UPDATE", "data": monitoring_service.get_status()})
