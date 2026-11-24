# HƯỚNG DẪN TRIỂN KHAI & KIỂM THỬ HỆ THỐNG NIDS CNN-LSTM (WINDOWS & KALI LINUX)

Tài liệu này hướng dẫn chi tiết quy trình cài đặt, cấu hình quyền bắt gói tin tối thiểu, khởi chạy hệ thống phát hiện tấn công mạng theo thời gian thực (**CNN-LSTM NIDS**) trên **Windows** (môi trường phát triển & replay) và **Kali Linux** (môi trường giám sát mạng thực tế trong Lab), cùng kế hoạch kiểm thử 6 kịch bản mạng.

---

## 1. Cấu trúc Artifact Mô hình đã Import

Hệ thống sử dụng trực tiếp 2 bộ trọng số **TorchScript CNN-LSTM** đã huấn luyện trên Google Colab (tuyệt đối không huấn luyện lại, không gộp trọng số và không dùng chung bộ tiền xử lý):

```text
artifacts/
├── CIC-IDS2017/                     # Profile mặc định: Giám sát tổng quát (70 features -> 12 classes)
│   ├── cnn_lstm.pt                  # TorchScript FlowFeatureCNNLSTM (Batch, 70)
│   ├── best.pt                      # Checkpoint PyTorch gốc (Epoch 7)
│   ├── preprocessor.joblib          # SimpleImputer(median) + StandardScaler + LabelEncoder
│   ├── gaussian.joblib              # LedoitWolf Gaussian model (threshold = 263.7635)
│   ├── config.json                  # Cấu hình chính thức
│   ├── label_mapping.json           # Ánh xạ 12 lớp
│   ├── test_metrics.json            # Kết quả Test offline (Acc: 94.49%, Macro-F1: 86.06%)
│   ├── classification_report.csv
│   ├── confusion_matrix.csv
│   ├── model_comparison.csv
│   └── training_history.csv
└── NIDS_Model_v1/                   # Profile CIC-DDoS2019 V2: Chuyên sâu DoS/DDoS (8x66 -> 17 classes)
    ├── cnn_lstm.pt                  # TorchScript TemporalCNNLSTM (Batch, 8, 66)
    ├── best.pt                      # Checkpoint PyTorch gốc (Epoch 22)
    ├── temporal_preprocessor.joblib # SimpleImputer(median) + StandardScaler (66 features)
    ├── gaussian_temporal.joblib     # LedoitWolf Gaussian model (threshold = 185.0203)
    ├── config.json                  # Cấu hình chính thức (window_size=8, stride=8, max_window_seconds=300)
    ├── label_mapping.json           # Ánh xạ 17 lớp
    ├── test_metrics.csv             # Binary Acc: 99.69%, Multiclass 17-class Acc: 55.36%
    ├── classification_report.csv
    ├── confusion_matrix.csv
    ├── pipeline_comparison.csv
    └── validation_comparison.csv
```

> [!NOTE]
> Hệ thống tự động nhận diện thư mục `artifacts/NIDS_Model_v1` hoặc `artifacts/CIC-DDoS2019` cho profile `CIC-DDoS2019`. Bạn không cần đổi tên thư mục thủ công.

---

## 2. Cài đặt và Khởi chạy trên Windows (Development & Replay)

### 2.1. Cài đặt môi trường Python (`.venv`)

Mở PowerShell tại thư mục gốc `D:\NIDS-System`:

```powershell
# 1. Tạo virtual environment
python -m venv .venv

# 2. Cài đặt các thư viện cần thiết
.\.venv\Scripts\pip.exe install -r requirements.txt
```

### 2.2. Khởi chạy FastAPI Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
*(Hoặc chạy nhanh file `scripts\start_backend_win.bat`)*.
- REST API & Swagger Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/health`
- WebSocket Realtime: `ws://127.0.0.1:8000/ws/live`

### 2.3. Cài đặt và Khởi chạy React SOC Dashboard

Mở một cửa sổ PowerShell thứ hai:

```powershell
cd frontend
npm install
npm run dev
```
*(Hoặc chạy nhanh file `scripts\start_frontend_win.bat`)*.
- Mở trình duyệt tại: `http://127.0.0.1:5173`

### 2.4. Chạy CSV Replay và PCAP Replay

1. Trên giao diện Web Dashboard, mở trang **2. Live Monitoring**.
2. Chọn Model Profile:
   - `CIC-IDS2017` (suy luận từng flow đơn lẻ, 70 đặc trưng, 12 lớp).
   - `CIC-DDoS2019` (gom theo `Source IP`, cửa sổ 8 flows, `stride=8`, `0 < duration <= 300s`, 66 đặc trưng, 17 lớp).
3. Chọn Data Source:
   - `CSV_REPLAY`: Phát lại file CSV mẫu có sẵn hoặc upload file CSV trích xuất từ CICFlowMeter.
   - `PCAP_REPLAY`: Đọc file `.pcap` bằng Scapy `PcapReader`, gom gói tin thành bidirectional flow qua `FlowExtractor` (70 đặc trưng) và đưa vào CNN-LSTM.
4. Nhấn **Start Monitoring** để xem luồng cảnh báo truyền trực tiếp qua WebSocket, hoặc chọn file `.csv` / `.pcap` từ máy tính rồi nhấn **Chạy File Upload**.

---

## 3. Triển khai trên Kali Linux (Giai đoạn 4 — Realtime Monitoring)

### 3.1. Cài đặt gói hệ thống và môi trường ảo trên Kali Linux

Trên máy Kali Linux (trong môi trường Lab cách ly):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libpcap-dev tcpdump nodejs npm

# Di chuyển vào thư mục dự án
cd ~/NIDS-System

# Tạo môi trường ảo Python
python3 -m venv .venv
source .venv/bin/activate

# Cài đặt PyTorch CPU và các dependency
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.2. Cấu hình quyền Packet Capture tối thiểu (Least-Privilege Capture)

Để Scapy có thể bắt gói tin trên card mạng (`eth0`, `ens33`, `wlan0`) mà **không cần chạy toàn bộ ứng dụng web dưới quyền `root`**, cấp capability `cap_net_raw` và `cap_net_admin` cho binary Python trong `.venv`:

```bash
# Cấp quyền đọc raw socket cho binary Python thực tế của virtualenv
REAL_PYTHON="$(readlink -f .venv/bin/python3)"
sudo setcap cap_net_raw,cap_net_admin=eip "${REAL_PYTHON}"

# Kiểm tra lại capability
getcap "${REAL_PYTHON}"
# Kết quả mong đợi: /usr/bin/python3.11 cap_net_admin,cap_net_raw=eip
```

> [!CAUTION]
> Khi hoàn tất thử nghiệm trên Kali Linux, bạn có thể thu hồi quyền này bằng lệnh:
> `sudo setcap -r "$(readlink -f .venv/bin/python3)"`

### 3.3. Kiểm tra và lựa chọn Network Interface

```bash
ip -br addr show
```
Xác định tên card mạng của máy Kali trong mạng Lab (ví dụ `eth0` hoặc `ens33`).

### 3.4. Khởi chạy Backend và Frontend trên Kali Linux

```bash
# Terminal 1: Khởi chạy FastAPI Backend (mặc định chỉ bind 127.0.0.1 để bảo mật)
chmod +x scripts/start_kali.sh
./scripts/start_kali.sh

# Terminal 2: Build và khởi chạy Frontend
cd frontend
npm install
npm run build
npm run preview -- --host 127.0.0.1 --port 4173
```

Mở trình duyệt trên Kali Linux tại `http://127.0.0.1:4173`:
1. Vào trang **2. Live Monitoring**.
2. Chọn Profile (`CIC-IDS2017` hoặc `CIC-DDoS2019`).
3. Chọn nguồn dữ liệu `LIVE` và chọn card mạng (`eth0`).
4. Nhấn **Start Monitoring**.

### 3.5. Dừng hệ thống an toàn (Graceful Shutdown)

1. Nhấn nút **Stop Monitoring** trên giao diện Web Dashboard (hoặc gọi `POST http://127.0.0.1:8000/api/monitoring/stop`) để `AsyncSniffer` dừng bắt gói, flush các flow còn trong bộ đệm và đóng phiên trong SQLite.
2. Nhấn `Ctrl + C` tại Terminal chạy Uvicorn và Frontend.

---

## 4. Kế hoạch Kiểm thử Mạng Thực tế trong Môi trường Lab Cách ly

> [!WARNING]
> Toàn bộ 6 kịch bản dưới đây **chỉ được phép thực hiện trong mạng Lab ảo hóa cách ly** (ví dụ: Host-Only / Internal Network trên VMware hoặc VirtualBox gồm 1 máy Kali NIDS `192.168.56.10` và 1 máy tạo lưu lượng kiểm thử `192.168.56.20`). Tuyệt đối không chạy quét mạng hoặc tạo lưu lượng tấn công ra mạng bên ngoài.

### 4.1. Bảng 6 kịch bản kiểm thử Lab

| Kịch bản | Mục tiêu kiểm thử | Profile sử dụng | Cách tạo lưu lượng an toàn trong Lab / PCAP | Kết quả kỳ vọng trên Dashboard |
|---|---|---|---|---|
| **1. Lưu lượng bình thường (Benign Baseline)** | Kiểm tra False Positive Rate và độ trễ suy luận cơ sở | `CIC-IDS2017` & `CIC-DDoS2019` | Duyệt web HTTP/HTTPS nội bộ, truy vấn DNS (`dig`), `curl` giữa 2 máy trong Lab | Trạng thái `BENIGN` (màu xanh), Gaussian score nằm dưới ngưỡng |
| **2. Lưu lượng PortScan** | Kiểm tra khả năng phát hiện dò quét cổng | `CIC-IDS2017` | Replay PCAP PortScan có nhãn hoặc trong Lab cách ly chạy `nmap -sS -p 20-100 192.168.56.10` | Phát hiện `ATTACK` — lớp `PortScan`, ghi nhận Source IP vào SQLite & đồ thị NetworkX |
| **3. Lưu lượng DoS / DDoS có nhãn** | Kiểm tra phân loại DoS/DDoS trên cả 2 profile | `CIC-IDS2017` & `CIC-DDoS2019` | Replay file CSV/PCAP có nhãn `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DrDoS_DNS` | `CIC-IDS2017` báo từng flow; `CIC-DDoS2019` đệm 7 flows `BUFFERING` và phát hiện `ATTACK` ở flow thứ 8 |
| **4. SYN Traffic kiểm thử** | Kiểm tra trích xuất cờ `SYN Flag Count` và cửa sổ Temporal 8-flow | `CIC-DDoS2019` | Replay PCAP/CSV có 8+ kết nối TCP SYN liên tiếp từ cùng một Source IP trong $\le 300\text{s}$ | Cửa sổ 8 flows chuyển từ `BUFFERING` sang `ATTACK` (`Syn`) |
| **5. Kết nối định kỳ mô phỏng Beaconing** | Kiểm tra thuật toán thống kê C2 Beaconing ($\mu, \sigma, CV$) | `CIC-IDS2017` | Script Python gọi `curl http://192.168.56.10:8000/api/health` lặp lại 8 lần, mỗi lần cách đúng $5.0\text{s}$ | Trang **4. Beaconing & Graph** hiển thị cặp IP với `Connections >= 5`, `CV <= 0.25`, trạng thái `SUSPECTED_BEACONING` |
| **6. Kết nối định kỳ hợp lệ & bất quy tắc** | Kiểm tra phân biệt kết nối ngẫu nhiên và tránh kết luận nhầm botnet | `CIC-IDS2017` | Tạo các kết nối có khoảng nghỉ ngẫu nhiên ($1\text{s}, 15\text{s}, 45\text{s}$) hoặc dịch vụ NTP chuẩn | Kết nối ngẫu nhiên có $CV > 0.25 \rightarrow$ `IRREGULAR`; kết nối định kỳ chỉ gắn nhãn `SUSPECTED_BEACONING` (không tự động báo ATTACK nếu CNN-LSTM dự đoán BENIGN) |

### 4.2. Các chỉ số đo lường & Báo cáo Coverage

Khi thu thập kết quả thực nghiệm trong Lab, hệ thống cung cấp trực tiếp qua `GET /api/monitoring/status` và `GET /api/stats/traffic`:
- **Inference Latency (`latency_avg_ms`, `latency_p50_ms`, `latency_p95_ms`)**: Thời gian tiền xử lý + TorchScript forward pass + Gaussian scoring trên CPU.
- **Total Flows Seen vs Total Inferences (`inference_coverage_ratio`)**:
  - Với `CIC-IDS2017`: `inference_coverage_ratio = 1.0` (100% flow hoàn thành đều được phân loại).
  - Với `CIC-DDoS2019`: Do `window_size = 8` và `stride = 8` theo từng `Source IP`, mỗi 8 flows hợp lệ tạo 1 lần inference cửa sổ. Các flow lẻ chưa đủ 8 hoặc vượt quá $300\text{s}$ được thống kê minh bạch trong `total_buffering` và `buffered_ips`, không bị ẩn khỏi báo cáo coverage.
- **Dropped Packet / Flow Count (`flows_dropped`)**: Số lượng gói/flow bị bỏ qua nếu hàng đợi bounded queue đầy khi chịu tải cao.
- **Accuracy, Precision, Recall, FPR**: Chỉ tính toán khi chạy trên dữ liệu CSV hoặc PCAP có cột nhãn thực tế (`ground_truth_label`).
