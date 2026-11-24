"""Unit tests for Phase 2: Packet Capture, Flow Extraction, CSV/PCAP Replay, and Temporal Window."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest
from scapy.all import IP, TCP, UDP, Raw, wrpcap  # type: ignore

from backend.app.core.inference import InferenceEngine
from backend.app.core.model_registry import ModelRegistry
from backend.app.network.flow_extractor import CompletedFlow, FlowExtractor, ParsedPacket
from backend.app.network.packet_capture import (
    iter_csv_flows,
    list_network_interfaces,
    read_pcap_flows,
)
from backend.app.network.temporal_window import TemporalWindowBuffer


@pytest.fixture(scope="module")
def registry() -> ModelRegistry:
    reg = ModelRegistry()
    reg.load_all_profiles()
    return reg


@pytest.fixture(scope="module")
def engine(registry: ModelRegistry) -> InferenceEngine:
    return InferenceEngine(registry)


def test_list_network_interfaces() -> None:
    ifaces = list_network_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) >= 1
    assert "name" in ifaces[0]


def test_flow_extractor_produces_exact_70_and_66_features(
    registry: ModelRegistry, engine: InferenceEngine
) -> None:
    """Kiểm tra bộ trích xuất đặc trưng tạo đủ 70 features cho CIC-IDS2017 và 66 features cho CIC-DDoS2019."""
    p_ids = registry.get_profile("CIC-IDS2017")
    p_ddos = registry.get_profile("CIC-DDoS2019")

    extractor = FlowExtractor(flow_timeout_seconds=120.0, activity_timeout_seconds=5.0)

    # Mô phỏng một phiên TCP HTTP gồm 3 gói: SYN (fwd), SYN-ACK (bwd), PSH-ACK + payload + FIN (fwd)
    t0 = 1700000000.0
    p1 = ParsedPacket(
        timestamp=t0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.80",
        src_port=51234,
        dst_port=80,
        protocol=6,
        payload_bytes=0,
        header_bytes=20,
        tcp_window=8192,
        flag_syn=1,
    )
    p2 = ParsedPacket(
        timestamp=t0 + 0.010,  # +10,000 us
        src_ip="10.0.0.80",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=51234,
        protocol=6,
        payload_bytes=120,
        header_bytes=20,
        tcp_window=65535,
        flag_syn=1,
        flag_ack=1,
    )
    p3 = ParsedPacket(
        timestamp=t0 + 0.030,  # +30,000 us
        src_ip="192.168.1.10",
        dst_ip="10.0.0.80",
        src_port=51234,
        dst_port=80,
        protocol=6,
        payload_bytes=250,
        header_bytes=20,
        tcp_window=8192,
        flag_psh=1,
        flag_ack=1,
        flag_fin=1,
    )

    assert extractor.process_packet(p1) == []
    assert extractor.process_packet(p2) == []
    done_flows = extractor.process_packet(p3)
    assert len(done_flows) == 1

    flow = done_flows[0]
    assert flow.src_ip == "192.168.1.10"
    assert flow.dst_ip == "10.0.0.80"
    assert flow.dst_port == 80
    assert flow.packet_count == 3

    # Kiểm tra toàn bộ 70 đặc trưng đều có mặt và đúng công thức
    for feat in p_ids.feature_names:
        assert feat in flow.features, f"Missing CIC-IDS2017 feature: {feat}"
    for feat in p_ddos.feature_names:
        assert feat in flow.features, f"Missing CIC-DDoS2019 feature: {feat}"

    assert flow.features["Flow Duration"] == pytest.approx(30000.0, rel=1e-4)
    assert flow.features["Total Fwd Packets"] == 2.0
    assert flow.features["Total Backward Packets"] == 1.0
    assert flow.features["Total Length of Fwd Packets"] == 250.0
    assert flow.features["Total Length of Bwd Packets"] == 120.0
    assert flow.features["SYN Flag Count"] == 2.0
    assert flow.features["FIN Flag Count"] == 1.0
    assert flow.features["Fwd PSH Flags"] == 1.0
    assert flow.features["Init_Win_bytes_forward"] == 8192.0
    assert flow.features["Init_Win_bytes_backward"] == 65535.0
    assert flow.features["act_data_pkt_fwd"] == 1.0
    assert flow.features["min_seg_size_forward"] == 20.0

    # Đưa flow trích xuất trực tiếp vào CNN-LSTM của CIC-IDS2017 để kiểm tra tương thích
    pred = engine.predict_single_flow(flow.features, profile_id="CIC-IDS2017")
    assert pred.predicted_label in p_ids.class_names


def test_pcap_replay_and_csv_replay(
    tmp_path: Path, registry: ModelRegistry, engine: InferenceEngine
) -> None:
    """Kiểm tra đọc file PCAP thật bằng Scapy và đọc file CSV replay."""
    pcap_file = tmp_path / "sample_traffic.pcap"
    pkts = []
    base_time = 1700001000.0

    # Tạo 8 UDP flows từ cùng một Source IP 10.10.10.5 tới DNS 8.8.8.8:53
    for i in range(8):
        q_pkt = (
            IP(src="10.10.10.5", dst="8.8.8.8")
            / UDP(sport=40000 + i, dport=53)
            / Raw(load=b"DNS_QUERY_PAYLOAD_" + bytes([i]))
        )
        q_pkt.time = base_time + i * 0.5
        r_pkt = (
            IP(src="8.8.8.8", dst="10.10.10.5")
            / UDP(sport=53, dport=40000 + i)
            / Raw(load=b"DNS_RESPONSE_PAYLOAD_DATA_" + bytes([i]))
        )
        r_pkt.time = base_time + i * 0.5 + 0.02
        pkts.extend([q_pkt, r_pkt])

    wrpcap(str(pcap_file), pkts)

    flows, total_pkts = read_pcap_flows(pcap_file)
    assert total_pkts == 16
    assert len(flows) == 8

    # Kiểm tra đưa 8 flows từ PCAP qua TemporalWindowBuffer và suy luận trên CIC-DDoS2019
    win_buf = TemporalWindowBuffer(window_size=8, stride=8, max_window_seconds=300.0)
    statuses = []
    ready_result = None
    for f in flows:
        res = win_buf.add_flow(f)
        statuses.append(res.status)
        if res.status == "READY":
            ready_result = res

    assert statuses == ["BUFFERING"] * 7 + ["READY"]
    assert ready_result is not None
    assert ready_result.window_flows is not None
    assert len(ready_result.window_flows) == 8

    ddos_pred = engine.predict_temporal_window(
        [f.features for f in ready_result.window_flows], profile_id="CIC-DDoS2019"
    )
    assert ddos_pred.detection_status in ("BENIGN", "ATTACK")

    # Lưu 8 flows này ra CSV và kiểm tra iter_csv_flows
    p_ids = registry.get_profile("CIC-IDS2017")
    csv_file = tmp_path / "sample_flows.csv"
    rows = []
    for f in flows:
        r = {
            "Flow ID": f.flow_id,
            "Source IP": f.src_ip,
            "Source Port": f.src_port,
            "Destination IP": f.dst_ip,
            "Timestamp": f.timestamp_iso,
            "Label": "BENIGN",
            **f.features,
        }
        rows.append(r)
    pd.DataFrame(rows).to_csv(csv_file, index=False)

    replayed = list(iter_csv_flows(csv_file, expected_features=p_ids.feature_names))
    assert len(replayed) == 8
    assert replayed[0].data_source == "CSV_REPLAY"
    assert replayed[0].ground_truth_label == "BENIGN"


def test_temporal_window_out_of_order_and_max_duration() -> None:
    """Kiểm tra Temporal Window xử lý flow đến sai thứ tự, stride=8 và loại flow quá 300 giây."""
    win_buf = TemporalWindowBuffer(
        window_size=8,
        stride=8,
        max_window_seconds=300.0,
        session_id="test-session-1",
    )

    def make_dummy_flow(src_ip: str, ts: float, idx: int) -> CompletedFlow:
        return CompletedFlow(
            flow_id=f"flow-{idx}",
            src_ip=src_ip,
            dst_ip="10.0.0.1",
            src_port=10000 + idx,
            dst_port=80,
            protocol=6,
            start_time=ts - 0.1,
            end_time=ts,
            timestamp_iso="2026-01-01T00:00:00Z",
            packet_count=2,
            features={"Destination Port": 80.0, "Protocol": 6.0},
        )

    # 1. Thêm 1 flow quá cũ (t = 100.0)
    res0 = win_buf.add_flow(make_dummy_flow("192.168.1.50", 100.0, 0))
    assert res0.status == "BUFFERING"

    # 2. Thêm 8 flows mới hơn cách flow đầu > 300s (t từ 500.0 đến 514.0), cố tình đảo thứ tự
    timestamps = [504.0, 500.0, 502.0, 510.0, 506.0, 508.0, 514.0, 512.0]
    last_res = None
    for i, ts in enumerate(timestamps, start=1):
        last_res = win_buf.add_flow(make_dummy_flow("192.168.1.50", ts, i))

    # Flow ở t=100.0 phải bị loại bỏ vì quá 300s, và 8 flows từ 500.0..514.0 phải tạo thành 1 window READY đã sắp xếp
    assert last_res is not None
    assert last_res.status == "READY"
    assert last_res.window_flows is not None
    assert len(last_res.window_flows) == 8
    extracted_times = [f.end_time for f in last_res.window_flows]
    assert extracted_times == sorted(timestamps)
    assert last_res.window_span_seconds == pytest.approx(14.0)
    # Sau khi emit window với stride=8, buffer của IP này phải trống
    assert win_buf.get_buffer_count("192.168.1.50") == 0
