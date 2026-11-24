"""Sample realistic flow generator from artifact statistics for safe offline CSV/PCAP replay testing.

Tạo dữ liệu kiểm thử hợp lệ (CSV và PCAP) dựa trên thống kê thực của tập dữ liệu đã lưu trong
artifact (`imputer.statistics_`, `scaler.mean_`, `scaler.scale_`) để người dùng có thể demo
ngay tính năng CSV Replay và PCAP Replay trên giao diện mà không cần tải lại 30GB dataset gốc.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pandas as pd

from backend.app.config import DATA_DIR
from backend.app.core.model_registry import model_registry


def ensure_sample_replay_files() -> dict[str, str]:
    """Tạo sẵn các file CSV và PCAP mẫu hợp lệ trong thư mục data/samples nếu chưa tồn tại."""
    samples_dir = DATA_DIR / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    cic2017_csv = samples_dir / "cic_ids2017_sample_flows.csv"
    cicddos_csv = samples_dir / "cic_ddos2019_temporal_sample_flows.csv"
    sample_pcap = samples_dir / "lab_mixed_traffic_sample.pcap"

    if not cic2017_csv.exists():
        _generate_cic2017_sample_csv(cic2017_csv)

    if not cicddos_csv.exists():
        _generate_cicddos2019_sample_csv(cicddos_csv)

    if not sample_pcap.exists():
        _generate_sample_pcap(sample_pcap)

    return {
        "cic_ids2017_csv": str(cic2017_csv),
        "cic_ddos2019_csv": str(cicddos_csv),
        "sample_pcap": str(sample_pcap),
    }


def _generate_cic2017_sample_csv(path: Path) -> None:
    p_ids = model_registry.load_profile("CIC-IDS2017")
    medians = p_ids.preprocessor_bundle["imputer"].statistics_
    means = p_ids.preprocessor_bundle["scaler"].mean_
    scales = p_ids.preprocessor_bundle["scaler"].scale_

    base_med = {feat: float(medians[i]) for i, feat in enumerate(p_ids.feature_names)}
    base_mean = {feat: float(means[i]) for i, feat in enumerate(p_ids.feature_names)}

    rows = []
    # Tạo 24 dòng gồm các mẫu BENIGN và các mẫu có đặc trưng lưu lượng tấn công điển hình (DDoS, PortScan, DoS Hulk, Bot)
    scenarios = [
        ("192.168.10.14", "192.168.10.50", 51200, 443, 6, "BENIGN", "median"),
        ("192.168.10.15", "192.168.10.50", 51201, 80, 6, "BENIGN", "median"),
        ("172.16.0.1", "192.168.10.50", 45120, 80, 6, "DDoS", "ddos"),
        ("172.16.0.1", "192.168.10.50", 45121, 80, 6, "DDoS", "ddos"),
        ("172.16.0.1", "192.168.10.50", 45122, 80, 6, "DoS Hulk", "hulk"),
        ("172.16.0.2", "192.168.10.50", 39001, 22, 6, "PortScan", "portscan"),
        ("172.16.0.2", "192.168.10.50", 39002, 21, 6, "PortScan", "portscan"),
        ("192.168.10.19", "205.174.165.73", 49500, 8080, 6, "Bot", "bot"),
    ]

    for idx in range(24):
        src_ip, dst_ip, sport, dport, proto, label, mode = scenarios[idx % len(scenarios)]
        feat = dict(base_med if mode == "median" else base_mean)
        feat["Destination Port"] = float(dport)
        feat["Protocol"] = float(proto)

        if mode == "ddos":
            feat["Flow Duration"] = 1200000.0
            feat["Total Fwd Packets"] = 8.0
            feat["Total Backward Packets"] = 6.0
            feat["Total Length of Bwd Packets"] = 11595.0
            feat["Bwd Packet Length Max"] = 5840.0
            feat["Bwd Packet Length Mean"] = 1932.5
            feat["Bwd Packet Length Std"] = 2180.0
            feat["Max Packet Length"] = 5840.0
            feat["Packet Length Mean"] = 830.0
            feat["Packet Length Std"] = 1520.0
            feat["Packet Length Variance"] = 2310400.0
            feat["Avg Bwd Segment Size"] = 1932.5
            feat["Subflow Bwd Bytes"] = 11595.0
            feat["Init_Win_bytes_forward"] = 256.0
            feat["Init_Win_bytes_backward"] = 229.0
        elif mode == "hulk":
            feat["Flow Duration"] = 95000000.0
            feat["Total Fwd Packets"] = 7.0
            feat["Total Backward Packets"] = 6.0
            feat["Total Length of Bwd Packets"] = 11595.0
            feat["Bwd Packet Length Max"] = 4344.0
            feat["Bwd Packet Length Mean"] = 1932.5
            feat["Flow IAT Max"] = 94000000.0
            feat["Flow IAT Std"] = 35000000.0
            feat["Idle Mean"] = 94000000.0
            feat["Idle Max"] = 94000000.0
            feat["Idle Min"] = 94000000.0
            feat["FIN Flag Count"] = 1.0
            feat["ACK Flag Count"] = 1.0
        elif mode == "portscan":
            feat["Flow Duration"] = 45.0
            feat["Total Fwd Packets"] = 1.0
            feat["Total Backward Packets"] = 1.0
            feat["Total Length of Fwd Packets"] = 0.0
            feat["Total Length of Bwd Packets"] = 0.0
            feat["Fwd Packet Length Max"] = 0.0
            feat["Bwd Packet Length Max"] = 0.0
            feat["Packet Length Mean"] = 0.0
            feat["PSH Flag Count"] = 1.0
            feat["RST Flag Count"] = 0.0
            feat["Init_Win_bytes_forward"] = 1024.0
            feat["Init_Win_bytes_backward"] = 0.0
            feat["min_seg_size_forward"] = 24.0
        elif mode == "bot":
            for i, f_name in enumerate(p_ids.feature_names):
                feat[f_name] = float(means[i] + 0.8 * scales[i])
            feat["Destination Port"] = 8080.0
            feat["Protocol"] = 6.0

        ts_sec = 10 + idx * 5
        rows.append(
            {
                "Flow ID": f"{src_ip}-{dst_ip}-{sport}-{dport}-{proto}-{idx}",
                "Source IP": src_ip,
                "Source Port": sport + idx,
                "Destination IP": dst_ip,
                "Timestamp": f"2026-11-24T10:00:{ts_sec % 60:02d}Z",
                "Label": label,
                **feat,
            }
        )

    pd.DataFrame(rows).to_csv(path, index=False)


def _generate_cicddos2019_sample_csv(path: Path) -> None:
    p_ddos = model_registry.load_profile("CIC-DDoS2019")
    means = p_ddos.preprocessor_bundle["scaler"].mean_
    medians = p_ddos.preprocessor_bundle["imputer"].statistics_

    base_mean = {feat: float(means[i]) for i, feat in enumerate(p_ddos.feature_names)}
    base_med = {feat: float(medians[i]) for i, feat in enumerate(p_ddos.feature_names)}

    rows = []
    # Tạo 24 flows (3 cửa sổ 8-flow: 2 cửa sổ từ 172.16.0.5 và 1 cửa sổ từ 192.168.50.10)
    for idx in range(24):
        src_ip = "172.16.0.5" if idx < 16 else "192.168.50.10"
        dst_ip = "192.168.50.1"
        feat = dict(base_mean if idx < 16 else base_med)
        if idx < 8:
            feat["Destination Port"] = 53.0
            feat["Protocol"] = 17.0
            label = "DrDoS_DNS"
        elif idx < 16:
            feat["Destination Port"] = 80.0
            feat["Protocol"] = 6.0
            feat["SYN Flag Count"] = 1.0
            label = "Syn"
        else:
            feat["Destination Port"] = 443.0
            feat["Protocol"] = 6.0
            label = "BENIGN"

        rows.append(
            {
                "Flow ID": f"{src_ip}-{dst_ip}-{50000+idx}-{int(feat['Destination Port'])}-{int(feat['Protocol'])}",
                "Source IP": src_ip,
                "Source Port": 50000 + idx,
                "Destination IP": dst_ip,
                "Timestamp": f"2026-11-24T10:05:{idx:02d}Z",
                "Label": label,
                **feat,
            }
        )

    pd.DataFrame(rows).to_csv(path, index=False)


def _generate_sample_pcap(path: Path) -> None:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.packet import Raw  # type: ignore
    from scapy.utils import wrpcap  # type: ignore

    pkts: List[object] = []
    base_ts = 1732442400.0

    # 1. Tạo 8 kết nối định kỳ từ 192.168.1.200 tới 198.51.100.42 (mỗi 5.0 giây) để minh họa cả Flow & Beaconing
    for i in range(8):
        t = base_ts + i * 5.0
        syn = IP(src="192.168.1.200", dst="198.51.100.42") / TCP(
            sport=42000 + i, dport=443, flags="S", window=8192
        )
        syn.time = t
        syn_ack = IP(src="198.51.100.42", dst="192.168.1.200") / TCP(
            sport=443, dport=42000 + i, flags="SA", window=65535
        )
        syn_ack.time = t + 0.005
        psh_fin = (
            IP(src="192.168.1.200", dst="198.51.100.42")
            / TCP(sport=42000 + i, dport=443, flags="PAF", window=8192)
            / Raw(load=b"GET /heartbeat HTTP/1.1\r\nHost: c2.example\r\n\r\n")
        )
        psh_fin.time = t + 0.015
        pkts.extend([syn, syn_ack, psh_fin])

    # 2. Tạo 8 UDP flows từ 172.16.0.77 tới 10.0.0.53 (đủ 1 temporal window 8 flows cho CIC-DDoS2019)
    for j in range(8):
        t = base_ts + 50.0 + j * 0.5
        u1 = (
            IP(src="172.16.0.77", dst="10.0.0.53")
            / UDP(sport=53000 + j, dport=53)
            / Raw(load=b"A" * 512)
        )
        u1.time = t
        u2 = (
            IP(src="10.0.0.53", dst="172.16.0.77")
            / UDP(sport=53, dport=53000 + j)
            / Raw(load=b"B" * 1024)
        )
        u2.time = t + 0.002
        pkts.extend([u1, u2])

    wrpcap(str(path), pkts)
