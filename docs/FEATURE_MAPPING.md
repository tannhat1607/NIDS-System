# TÀI LIỆU ÁNH XẠ ĐẶC TRƯNG MẠNG (FEATURE MAPPING) — CICFLOWMETER COMPATIBLE

Tài liệu này mô tả chi tiết công thức tính toán, đơn vị đo và trạng thái kiểm chứng của bộ trích xuất đặc trưng mạng (`backend/app/network/flow_extractor.py`) dùng cho hai model profile CNN-LSTM:
- **CIC-IDS2017**: 70 đặc trưng (`single_flow`, shape `(Batch, 70)`).
- **CIC-DDoS2019 V2**: 66 đặc trưng (`temporal_window`, shape `(Batch, 8, 66)`).

---

## 1. Quy ước chung theo chuẩn CICFlowMeter (ISCXFlowMeter)

1. **Chiều giao tiếp (Forward / Backward Direction)**:
   - Gói tin đầu tiên khởi tạo một flow xác định chiều **Forward (`Fwd`)**: `(src_ip, dst_ip, src_port, dst_port, protocol)`.
   - Các gói tin đi theo chiều ngược lại `(dst_ip -> src_ip, dst_port -> src_port, protocol)` trong cùng phiên được tính vào chiều **Backward (`Bwd`)**.
2. **Đơn vị thời gian**:
   - Toàn bộ các đặc trưng thời gian (`Flow Duration`, `Flow IAT *`, `Fwd IAT *`, `Bwd IAT *`, `Active *`, `Idle *`) được tính bằng **micro-giây ($\mu\text{s}$)** ($1\text{ s} = 1,000,000\ \mu\text{s}$).
   - Các đặc trưng tốc độ (`Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s`) được chuẩn hóa theo **giây ($\text{s}$)**.
3. **Đơn vị kích thước**:
   - Độ dài gói tin (`Packet Length`, `Total Length of Fwd/Bwd Packets`, `Avg Fwd/Bwd Segment Size`) tính theo **số byte của Transport Payload** (TCP/UDP payload bytes), khớp với `PacketInfo.getPayloadBytes()` trong mã nguồn Java của CICFlowMeter.
   - Độ dài Header (`Fwd/Bwd Header Length`, `min_seg_size_forward`) tính theo **số byte của Transport Header** (TCP header `dataofs * 4`, UDP header = `8` bytes).
4. **Ngưỡng thời gian (Timeouts)**:
   - `Flow Timeout`: $120\text{ s}$ ($120,000,000\ \mu\text{s}$).
   - `Activity Timeout` (tách chu kỳ Active / Idle): $5\text{ s}$ ($5,000,000\ \mu\text{s}$).
   - `Subflow Timeout` (tách Subflow): $1\text{ s}$ ($1,000,000\ \mu\text{s}$).

---

## 2. Bảng ánh xạ chi tiết 70 đặc trưng

| STT | Tên đặc trưng (Feature Name) | Có trong CIC-IDS2017 (70) | Có trong CIC-DDoS2019 (66) | Đơn vị đo | Công thức tính trong `FlowExtractor` | Trạng thái kiểm chứng |
|---:|---|:---:|:---:|---|---|---|
| 01 | `Destination Port` | Có | Có | Port number | Cổng đích của gói tin khởi tạo flow (`dst_port`) | Verified (Unit & PCAP Test) |
| 02 | `Protocol` | Có | Có | IANA number | Mã giao thức IP (`6` = TCP, `17` = UDP, `1` = ICMP) | Verified (Unit & PCAP Test) |
| 03 | `Flow Duration` | Có | Có | $\mu\text{s}$ | $(t_{\text{last}} - t_{\text{first}}) \times 10^6$ | Verified (Unit & PCAP Test) |
| 04 | `Total Fwd Packets` | Có | Có | Packets | Tổng số gói tin chiều Forward $N_{\text{fwd}}$ | Verified (Unit & PCAP Test) |
| 05 | `Total Backward Packets` | Có | Có | Packets | Tổng số gói tin chiều Backward $N_{\text{bwd}}$ | Verified (Unit & PCAP Test) |
| 06 | `Total Length of Fwd Packets` | Có | Có | Bytes | $\sum L_{\text{fwd}}$ (tổng payload bytes chiều Forward) | Verified (Unit & PCAP Test) |
| 07 | `Total Length of Bwd Packets` | Có | Có | Bytes | $\sum L_{\text{bwd}}$ (tổng payload bytes chiều Backward) | Verified (Unit & PCAP Test) |
| 08 | `Fwd Packet Length Max` | Có | Có | Bytes | $\max(L_{\text{fwd}})$ (0 nếu $N_{\text{fwd}}=0$) | Verified (Unit & PCAP Test) |
| 09 | `Fwd Packet Length Min` | Có | Có | Bytes | $\min(L_{\text{fwd}})$ (0 nếu $N_{\text{fwd}}=0$) | Verified (Unit & PCAP Test) |
| 10 | `Fwd Packet Length Mean` | Có | Có | Bytes | $\text{mean}(L_{\text{fwd}})$ | Verified (Unit & PCAP Test) |
| 11 | `Fwd Packet Length Std` | Có | Có | Bytes | Độ lệch chuẩn mẫu ($ddof=1$) của $L_{\text{fwd}}$ | Verified (Unit & PCAP Test) |
| 12 | `Bwd Packet Length Max` | Có | Có | Bytes | $\max(L_{\text{bwd}})$ (0 nếu $N_{\text{bwd}}=0$) | Verified (Unit & PCAP Test) |
| 13 | `Bwd Packet Length Min` | Có | Có | Bytes | $\min(L_{\text{bwd}})$ (0 nếu $N_{\text{bwd}}=0$) | Verified (Unit & PCAP Test) |
| 14 | `Bwd Packet Length Mean` | Có | Có | Bytes | $\text{mean}(L_{\text{bwd}})$ | Verified (Unit & PCAP Test) |
| 15 | `Bwd Packet Length Std` | Có | Có | Bytes | Độ lệch chuẩn mẫu ($ddof=1$) của $L_{\text{bwd}}$ | Verified (Unit & PCAP Test) |
| 16 | `Flow Bytes/s` | Có | Có | Bytes/s | $(\sum L_{\text{fwd}} + \sum L_{\text{bwd}}) / (\text{Flow Duration} / 10^6)$ | Verified (Unit & PCAP Test) |
| 17 | `Flow Packets/s` | Có | Có | Packets/s | $(N_{\text{fwd}} + N_{\text{bwd}}) / (\text{Flow Duration} / 10^6)$ | Verified (Unit & PCAP Test) |
| 18 | `Flow IAT Mean` | Có | Có | $\mu\text{s}$ | Trung bình khoảng cách thời gian $\Delta t_i \times 10^6$ giữa 2 gói liên tiếp | Verified (Unit & PCAP Test) |
| 19 | `Flow IAT Std` | Có | Có | $\mu\text{s}$ | Độ lệch chuẩn mẫu ($ddof=1$) của Flow IAT | Verified (Unit & PCAP Test) |
| 20 | `Flow IAT Max` | Có | Có | $\mu\text{s}$ | Giá trị cực đại của Flow IAT | Verified (Unit & PCAP Test) |
| 21 | `Flow IAT Min` | Có | Có | $\mu\text{s}$ | Giá trị cực tiểu của Flow IAT | Verified (Unit & PCAP Test) |
| 22 | `Fwd IAT Total` | Có | Có | $\mu\text{s}$ | Tổng khoảng thời gian giữa các gói chiều Forward | Verified (Unit & PCAP Test) |
| 23 | `Fwd IAT Mean` | Có | Có | $\mu\text{s}$ | Trung bình khoảng thời gian giữa các gói chiều Forward | Verified (Unit & PCAP Test) |
| 24 | `Fwd IAT Std` | Có | Có | $\mu\text{s}$ | Độ lệch chuẩn mẫu ($ddof=1$) của Fwd IAT | Verified (Unit & PCAP Test) |
| 25 | `Fwd IAT Max` | Có | Có | $\mu\text{s}$ | Giá trị cực đại của Fwd IAT | Verified (Unit & PCAP Test) |
| 26 | `Fwd IAT Min` | Có | Có | $\mu\text{s}$ | Giá trị cực tiểu của Fwd IAT | Verified (Unit & PCAP Test) |
| 27 | `Bwd IAT Total` | Có | Có | $\mu\text{s}$ | Tổng khoảng thời gian giữa các gói chiều Backward | Verified (Unit & PCAP Test) |
| 28 | `Bwd IAT Mean` | Có | Có | $\mu\text{s}$ | Trung bình khoảng thời gian giữa các gói chiều Backward | Verified (Unit & PCAP Test) |
| 29 | `Bwd IAT Std` | Có | Có | $\mu\text{s}$ | Độ lệch chuẩn mẫu ($ddof=1$) của Bwd IAT | Verified (Unit & PCAP Test) |
| 30 | `Bwd IAT Max` | Có | Có | $\mu\text{s}$ | Giá trị cực đại của Bwd IAT | Verified (Unit & PCAP Test) |
| 31 | `Bwd IAT Min` | Có | Có | $\mu\text{s}$ | Giá trị cực tiểu của Bwd IAT | Verified (Unit & PCAP Test) |
| 32 | `Fwd PSH Flags` | Có | Có | Count | Số gói tin chiều Forward bật cờ TCP `PSH` | Verified (Unit & PCAP Test) |
| 33 | `Fwd URG Flags` | Có | **Không** | Count | Số gói tin chiều Forward bật cờ TCP `URG` | Verified (Unit & PCAP Test) |
| 34 | `Fwd Header Length` | Có | Có | Bytes | Tổng số byte Transport Header của các gói chiều Forward | Verified (Unit & PCAP Test) |
| 35 | `Bwd Header Length` | Có | Có | Bytes | Tổng số byte Transport Header của các gói chiều Backward | Verified (Unit & PCAP Test) |
| 36 | `Fwd Packets/s` | Có | Có | Packets/s | $N_{\text{fwd}} / (\text{Flow Duration} / 10^6)$ | Verified (Unit & PCAP Test) |
| 37 | `Bwd Packets/s` | Có | Có | Packets/s | $N_{\text{bwd}} / (\text{Flow Duration} / 10^6)$ | Verified (Unit & PCAP Test) |
| 38 | `Min Packet Length` | Có | Có | Bytes | $\min(L_{\text{all}})$ | Verified (Unit & PCAP Test) |
| 39 | `Max Packet Length` | Có | Có | Bytes | $\max(L_{\text{all}})$ | Verified (Unit & PCAP Test) |
| 40 | `Packet Length Mean` | Có | Có | Bytes | $\text{mean}(L_{\text{all}})$ (theo quy ước CICFlowMeter) | Verified (Unit & PCAP Test) |
| 41 | `Packet Length Std` | Có | Có | Bytes | Độ lệch chuẩn mẫu ($ddof=1$) của $L_{\text{all}}$ | Verified (Unit & PCAP Test) |
| 42 | `Packet Length Variance` | Có | Có | $\text{Bytes}^2$ | Phương sai mẫu ($ddof=1$) của $L_{\text{all}}$ | Verified (Unit & PCAP Test) |
| 43 | `FIN Flag Count` | Có | **Không** | Count | Tổng số gói trong flow bật cờ TCP `FIN` (`0x01`) | Verified (Unit & PCAP Test) |
| 44 | `SYN Flag Count` | Có | Có | Count | Tổng số gói trong flow bật cờ TCP `SYN` (`0x02`) | Verified (Unit & PCAP Test) |
| 45 | `RST Flag Count` | Có | Có | Count | Tổng số gói trong flow bật cờ TCP `RST` (`0x04`) | Verified (Unit & PCAP Test) |
| 46 | `PSH Flag Count` | Có | **Không** | Count | Tổng số gói trong flow bật cờ TCP `PSH` (`0x08`) | Verified (Unit & PCAP Test) |
| 47 | `ACK Flag Count` | Có | Có | Count | Tổng số gói trong flow bật cờ TCP `ACK` (`0x10`) | Verified (Unit & PCAP Test) |
| 48 | `URG Flag Count` | Có | Có | Count | Tổng số gói trong flow bật cờ TCP `URG` (`0x20`) | Verified (Unit & PCAP Test) |
| 49 | `CWE Flag Count` | Có | Có | Count | Tổng số gói trong flow bật cờ TCP `CWR/CWE` (`0x80`) | Verified (Unit & PCAP Test) |
| 50 | `ECE Flag Count` | Có | **Không** | Count | Tổng số gói trong flow bật cờ TCP `ECE` (`0x40`) | Verified (Unit & PCAP Test) |
| 51 | `Down/Up Ratio` | Có | Có | Ratio | $\lfloor N_{\text{bwd}} / N_{\text{fwd}} \rfloor$ (0 nếu $N_{\text{fwd}}=0$) | Verified (Unit & PCAP Test) |
| 52 | `Average Packet Size` | Có | Có | Bytes | $\sum L_{\text{all}} / (N_{\text{fwd}} + N_{\text{bwd}})$ | Verified (Unit & PCAP Test) |
| 53 | `Avg Fwd Segment Size` | Có | Có | Bytes | Bằng `Fwd Packet Length Mean` | Verified (Unit & PCAP Test) |
| 54 | `Avg Bwd Segment Size` | Có | Có | Bytes | Bằng `Bwd Packet Length Mean` | Verified (Unit & PCAP Test) |
| 55 | `Subflow Fwd Packets` | Có | Có | Packets/Subflow | $\lfloor N_{\text{fwd}} / N_{\text{subflows}} \rfloor$ | Verified (Unit & PCAP Test) |
| 56 | `Subflow Fwd Bytes` | Có | Có | Bytes/Subflow | $\lfloor \sum L_{\text{fwd}} / N_{\text{subflows}} \rfloor$ | Verified (Unit & PCAP Test) |
| 57 | `Subflow Bwd Packets` | Có | Có | Packets/Subflow | $\lfloor N_{\text{bwd}} / N_{\text{subflows}} \rfloor$ | Verified (Unit & PCAP Test) |
| 58 | `Subflow Bwd Bytes` | Có | Có | Bytes/Subflow | $\lfloor \sum L_{\text{bwd}} / N_{\text{subflows}} \rfloor$ | Verified (Unit & PCAP Test) |
| 59 | `Init_Win_bytes_forward` | Có | Có | Bytes | Trường TCP Window của gói TCP đầu tiên chiều Forward (`-1` cho UDP) | Verified (Unit & PCAP Test) |
| 60 | `Init_Win_bytes_backward` | Có | Có | Bytes | Trường TCP Window của gói TCP đầu tiên chiều Backward (`-1` cho UDP) | Verified (Unit & PCAP Test) |
| 61 | `act_data_pkt_fwd` | Có | Có | Packets | Số gói chiều Forward có `payload_bytes >= 1` | Verified (Unit & PCAP Test) |
| 62 | `min_seg_size_forward` | Có | Có | Bytes | Độ dài Transport Header nhỏ nhất chiều Forward | Verified (Unit & PCAP Test) |
| 63 | `Active Mean` | Có | Có | $\mu\text{s}$ | Trung bình thời gian các chu kỳ hoạt động (ngưỡng tách 5s) | Verified (Unit & PCAP Test) |
| 64 | `Active Std` | Có | Có | $\mu\text{s}$ | Độ lệch chuẩn mẫu ($ddof=1$) của các chu kỳ Active | Verified (Unit & PCAP Test) |
| 65 | `Active Max` | Có | Có | $\mu\text{s}$ | Giá trị cực đại của các chu kỳ Active | Verified (Unit & PCAP Test) |
| 66 | `Active Min` | Có | Có | $\mu\text{s}$ | Giá trị cực tiểu của các chu kỳ Active | Verified (Unit & PCAP Test) |
| 67 | `Idle Mean` | Có | Có | $\mu\text{s}$ | Trung bình khoảng thời gian nghỉ ($> 5\text{ s}$) giữa các chu kỳ Active | Verified (Unit & PCAP Test) |
| 68 | `Idle Std` | Có | Có | $\mu\text{s}$ | Độ lệch chuẩn mẫu ($ddof=1$) của các khoảng Idle | Verified (Unit & PCAP Test) |
| 69 | `Idle Max` | Có | Có | $\mu\text{s}$ | Giá trị cực đại của các khoảng Idle | Verified (Unit & PCAP Test) |
| 70 | `Idle Min` | Có | Có | $\mu\text{s}$ | Giá trị cực tiểu của các khoảng Idle | Verified (Unit & PCAP Test) |

---

## 3. Trạng thái xác thực (Validation Status)

- **CSV Replay (`CSV_REPLAY`)**: **VERIFIED** — Đọc trực tiếp 70 đặc trưng (CIC-IDS2017) và 66 đặc trưng (CIC-DDoS2019), kiểm tra nghiêm ngặt qua `canonicalize_feature_dict` và tiền xử lý khớp tuyệt đối với Colab pipeline.
- **PCAP Replay (`PCAP_REPLAY`)**: **VERIFIED (Local Synthetic & Real Packet Structure)** — Gói tin Scapy được bóc tách đầy đủ 70 đặc trưng chuẩn CICFlowMeter, vượt qua toàn bộ kiểm tra schema, kiểu dữ liệu, đơn vị và suy luận trên cả hai model CNN-LSTM.
- **Live Capture (`LIVE`)**: **READY FOR LINUX VALIDATION** — Trên môi trường phát triển hiện tại (Windows), toàn bộ luồng `AsyncSniffer` + bounded queue + `FlowExtractor` + `TemporalWindowBuffer` đã được xây dựng và kiểm thử tích hợp; việc bắt gói tin thực tế trên card mạng Kali Linux (`eth0`/`wlan0`) sẵn sàng để kiểm chứng trực tiếp trong môi trường Lab Linux được cấp phép.
