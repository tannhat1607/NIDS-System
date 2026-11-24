# TRIỂN KHAI HỆ THỐNG PHÁT HIỆN TẤN CÔNG MẠNG REALTIME BẰNG CNN-LSTM

## 1. Vai trò và nhiệm vụ

Bạn là Senior AI Engineer, Full-stack Developer và Network Security Engineer.

Hãy trực tiếp xây dựng sản phẩm Network Intrusion Detection System (NIDS) dựa trên thuật toán CNN-LSTM đã được huấn luyện trên Google Colab.

Tên đề tài: Phát hiện tấn công mạng dựa trên mô hình CNN mở rộng kết hợp LSTM.

Các giai đoạn chuẩn bị dữ liệu, EDA, tiền xử lý, huấn luyện, đánh giá, so sánh và lựa chọn mô hình đã hoàn thành.

Hiện tại chỉ thực hiện **Giai đoạn 4: Triển khai hệ thống phát hiện tấn công mạng theo thời gian thực trên Linux**.

Tôi đã import các artifact cần thiết từ Google Colab vào workspace hiện tại.

Hãy trực tiếp kiểm tra file, viết source code, cài đặt dependency cần thiết trong môi trường dự án, kiểm thử và hoàn thiện sản phẩm.

Không chỉ đưa ra kế hoạch hoặc code minh họa.

## 2. Phạm vi và nguyên tắc

- Chỉ sử dụng CNN-LSTM làm thuật toán AI chính thức.
- Sử dụng hai bộ trọng số CNN-LSTM đã huấn luyện độc lập trên hai dataset.
- Không triển khai CNN-BiLSTM hoặc các mô hình ML baseline.
- Không huấn luyện lại.
- Không tải lại dataset huấn luyện.
- Không thực hiện lại EDA.
- Không tối ưu hyperparameter.
- Không chỉnh sửa trọng số và bộ tiền xử lý đã export.
- Không triển khai Ensemble.
- Không phát triển đăng nhập, phân quyền, microservices hoặc tự động chặn IP trong MVP.
- Ưu tiên sản phẩm hoạt động ổn định, chính xác, dễ triển khai và dễ demo.

## 3. Artifact và thông tin mô hình

Kiểm tra các file đã được import trong workspace. Không giả định đường dẫn thực tế nếu cấu trúc thư mục khác với dự kiến.

Cấu trúc artifact đề xuất:

```text
artifacts/
├── CIC-IDS2017/
│   ├── cnn_lstm.pt
│   ├── best.pt
│   ├── preprocessor.joblib
│   ├── gaussian.joblib
│   ├── config.json
│   ├── label_mapping.json
│   ├── test_metrics.json
│   ├── classification_report.csv
│   ├── confusion_matrix.csv
│   └── environment.txt
└── CIC-DDoS2019/
    ├── cnn_lstm.pt
    ├── best.pt
    ├── temporal_preprocessor.joblib
    ├── gaussian_temporal.joblib
    ├── config.json
    ├── label_mapping.json
    ├── test_metrics.csv
    ├── classification_report.csv
    ├── confusion_matrix.csv
    ├── pipeline_comparison.csv
    └── validation_comparison.csv
```

### 3.1. CNN-LSTM — CIC-IDS2017

- Input shape: (Batch, 70).
- 70 đặc trưng.
- 12 lớp phân loại.
- Phân loại từng network flow.
- Mô hình tự reshape dữ liệu bên trong forward().
- Best epoch: 7.
- Test Accuracy: 94.4855%.
- Test Macro-F1: 86.0558%.

Các lớp:

BENIGN, Bot, DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, PortScan, SSH-Patator, WebAttack-BruteForce, WebAttack-XSS.

Mục đích: phát hiện đa dạng các nhóm tấn công mạng.

Lưu ý: đây là Feature-sequence CNN-LSTM, LSTM xử lý chuỗi đặc trưng sau CNN, không phải chuỗi nhiều flow theo thời gian.

### 3.2. CNN-LSTM — CIC-DDoS2019 V2

- Input shape: (Batch, 8, 66).
- 66 đặc trưng mỗi flow.
- 17 lớp phân loại.
- Window size: 8 flows.
- Stride: 8.
- Grouping: Source IP.
- Sắp xếp flow theo timestamp.
- Window duration: lớn hơn 0 và không vượt quá 300 giây.
- Target: nhãn của flow cuối cùng.
- Best epoch: 22.

Kết quả Test offline:

- Binary Accuracy: 99.69%.
- Attack Precision: 99.86%.
- Attack Recall: 99.81%.
- Binary F1: 99.84%.
- False Positive Rate: 3.33%.
- Multiclass Accuracy: 55.36%.
- Macro-F1: 52.43%.

Mục đích: phát hiện và phân loại chuyên sâu các biến thể DoS/DDoS.

Đây là Temporal CNN-LSTM sử dụng chuỗi tám flow liên tiếp.

### 3.3. Quy tắc sử dụng

Hai model profile sử dụng cùng họ thuật toán CNN-LSTM nhưng có kiến trúc cụ thể, kích thước đầu vào, trọng số, scaler và label mapping riêng.

Không sử dụng chung preprocessor.

Không gộp trọng số.

Không tự ý hợp nhất xác suất dự đoán.

Đọc config.json và label_mapping.json làm nguồn cấu hình chính thức.

Ưu tiên CIC-IDS2017 làm profile giám sát tổng quát mặc định; CIC-DDoS2019 là profile phân tích chuyên sâu DDoS.

Cho phép người dùng chọn profile trước khi bắt đầu monitoring. Không cần chạy đồng thời hai profile trong MVP.

## 4. Technology Stack

Development:

- Windows.
- Visual Studio Code.
- Antigravity hoặc Codex.
- Git.

Backend:

- Python.
- PyTorch.
- NumPy.
- Pandas.
- Scikit-learn.
- Joblib.
- Scapy.
- NetworkX.
- FastAPI.
- Uvicorn.
- WebSocket.
- SQLite.
- Pytest.

Frontend:

- React.
- TypeScript.
- Vite.
- Tailwind CSS.
- Recharts.
- Lucide Icons.

Deployment:

- Kali Linux.
- CPU inference.
- Python virtual environment.

Kiểm tra phiên bản Python và dependency tương thích với artifact trước khi cài đặt.

## 5. Kiến trúc hệ thống

```text
Network Traffic
       |
Scapy Packet Capture
       |
Flow Aggregation
       |
Feature Extraction
       |
Model Profile Selection
       |
       +-- CIC-IDS2017
       |     Preprocessing 70 features
       |     CNN-LSTM
       |
       +-- CIC-DDoS2019
             Preprocessing 66 features
             Temporal Window 8 flows
             CNN-LSTM
       |
Detection Engine
       |
Gaussian / Beaconing / Graph Analysis
       |
Alert Logging + SQLite
       |
FastAPI + WebSocket
       |
React Dashboard
```

Sử dụng kiến trúc Modular Monolith đơn giản.

Tách biệt packet capture, feature extraction, AI inference, detection, database và API.

## 6. Cấu trúc thư mục đề xuất

```text
NIDS-System/
├── artifacts/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── core/
│   │   │   ├── model_registry.py
│   │   │   ├── preprocessing.py
│   │   │   ├── inference.py
│   │   │   └── detection_engine.py
│   │   ├── network/
│   │   │   ├── packet_capture.py
│   │   │   ├── flow_extractor.py
│   │   │   └── temporal_window.py
│   │   ├── analysis/
│   │   │   ├── gaussian.py
│   │   │   ├── beaconing.py
│   │   │   └── graph_analysis.py
│   │   ├── api/
│   │   └── database/
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   └── types/
│   └── package.json
├── data/
├── logs/
├── scripts/
├── docs/
├── .gitignore
└── README.md
```

Có thể điều chỉnh theo workspace thực tế. Không tạo cấu trúc quá phức tạp.

## 7. Phase 1 — Load Model và AI Inference

Xây dựng Model Registry để quản lý hai profile CNN-LSTM.

Thực hiện:

- Load TorchScript cnn_lstm.pt.
- Load preprocessor tương ứng.
- Load Gaussian artifact.
- Đọc config và label mapping.
- Kiểm tra feature names, số feature và số class.
- Sử dụng model.eval() và torch.inference_mode().
- Load model một lần khi khởi động hoặc lựa chọn profile.
- Sử dụng CPU.
- Không load lại model cho mỗi request.

Preprocessing:

- Sắp xếp đúng thứ tự đặc trưng.
- Xử lý NaN và Infinity đúng training pipeline.
- Sử dụng imputer và scaler đã fit.
- Không fit lại scaler.
- Không chuẩn hóa hai lần.
- Chuyển thành float32.
- Tạo tensor đúng kích thước của từng profile.

Inference:

- Forward pass.
- Softmax.
- Argmax.
- Ánh xạ class index thành class name.
- Xác định BENIGN hoặc ATTACK.
- Tính class score.
- Tính tổng Softmax score của các lớp ATTACK.
- Đo inference latency.

Sử dụng quy tắc argmax giống thực nghiệm trên Colab. Không tự ý thay đổi threshold phát hiện.

Kiểm thử khả năng load và inference của cả hai profile trước khi tiếp tục.

Nếu có fixture từ Colab, kiểm tra tính nhất quán giữa đầu ra local và Colab.

## 8. Phase 2 — Bắt gói tin và trích xuất đặc trưng

Sử dụng Scapy để:

- Liệt kê network interfaces.
- Bắt packet trên interface được lựa chọn.
- Start/stop capture.
- Đọc PCAP offline.
- Lấy timestamp và thông tin giao tiếp mạng.
- Gom packet thành bidirectional network flow.
- Quản lý forward/backward direction.
- Quản lý flow timeout.
- Giới hạn bộ nhớ sử dụng.

Hỗ trợ ba nguồn dữ liệu:

- CSV Replay.
- PCAP Replay.
- Live Capture.

### Yêu cầu bắt buộc về feature extraction

Đọc chính xác feature_names của từng profile.

Xây dựng bộ trích xuất đặc trưng tương thích với CICFlowMeter.

Phải đảm bảo đúng:

- Tên và thứ tự feature.
- Công thức tính.
- Đơn vị đo.
- Flow duration.
- Packet length.
- Packet count.
- Forward/backward direction.
- Inter-arrival time.
- TCP flags.
- Header length.
- Active/idle statistics.
- Subflow statistics.
- Initial TCP window size.
- Flow timeout.

Ưu tiên tận dụng bộ trích xuất tương thích đã có thay vì tự viết lại toàn bộ nếu có giải pháp phù hợp.

Tạo docs/FEATURE_MAPPING.md ghi rõ cách tính, đơn vị và trạng thái kiểm chứng của từng feature.

Không tạo feature giả.

Không random dữ liệu đầu vào.

Không tự động điền 0 cho đặc trưng chưa tính được.

Phải phân biệt missing value hợp lệ với feature chưa được triển khai.

Kiểm thử feature extraction bằng PCAP và reference CSV từ cùng nguồn nếu được cung cấp.

Nếu chưa xác thực được feature compatibility, hoàn thiện CSV replay trước và đánh dấu live inference chưa được xác thực. Không tuyên bố realtime detection hoạt động chính xác khi chưa kiểm chứng.

### Temporal Window

Chỉ áp dụng cho CIC-DDoS2019:

- Gom flow theo Source IP.
- Sắp xếp theo timestamp.
- Window size = 8.
- Stride = 8.
- Window duration lớn hơn 0 và không vượt quá 300 giây.
- Không trộn flow từ các session khác nhau.
- Xử lý flow đến sai thứ tự.
- Không sử dụng dữ liệu tương lai ngoài cửa sổ.
- Không padding bằng flow giả.
- Chỉ inference khi đủ tám flow hợp lệ.
- Nếu chưa đủ dữ liệu, trả trạng thái BUFFERING.

CIC-IDS2017 thực hiện inference trên từng flow đã hoàn thành.

## 9. Phase 3 — Detection Engine

CNN-LSTM là mô hình quyết định BENIGN hoặc ATTACK.

Kết quả cảnh báo bao gồm:

- Thời gian phát hiện.
- Source IP.
- Destination IP.
- Source Port.
- Destination Port.
- Protocol.
- Detection status.
- Predicted attack type.
- Class score.
- Attack score.
- Gaussian anomaly score.
- Inference latency.
- Dataset profile.
- Monitoring session.
- Data source.

### Gaussian Anomaly Detection

Sử dụng Gaussian artifact tương ứng với từng profile.

Tính squared Mahalanobis distance và so sánh với threshold đã lưu.

Gaussian chỉ cung cấp anomaly score và anomaly flag.

Không sử dụng Gaussian làm hard gate.

Không tự động phủ quyết kết quả CNN-LSTM.

Không tự động tạo ATTACK alert chỉ vì Gaussian vượt ngưỡng.

### Beaconing Detection

Xây dựng phương pháp thống kê cơ bản:

- Gom kết nối theo Source IP và Destination IP.
- Tính khoảng thời gian giữa các kết nối.
- Mean interval.
- Standard deviation.
- Coefficient of variation.
- Minimum connection count.
- Phát hiện kết nối có tính chu kỳ.

Kết quả chỉ là suspected beaconing.

Không kết luận kết nối định kỳ chắc chắn là botnet.

Không tuyên bố sử dụng LSTM chuyên biệt cho Beaconing vì chưa có mô hình tương ứng được xác thực.

### Graph Analysis

Sử dụng NetworkX:

- Node là IP.
- Edge là kết nối giữa các IP.
- Edge weight là số flow.
- Degree centrality.
- Reciprocity.
- Hub nodes.
- Dấu hiệu cấu trúc giao tiếp tập trung.
- Dấu hiệu P2P.

Chỉ xem kết quả là tín hiệu nghi ngờ bổ trợ.

Giới hạn bộ nhớ, số node và thời gian lưu graph.

## 10. Phase 4 — FastAPI, WebSocket và SQLite

Xây dựng REST API hỗ trợ:

- Kiểm tra system health.
- Danh sách model profile.
- Lựa chọn model profile.
- Danh sách network interfaces.
- Start monitoring.
- Stop monitoring.
- Monitoring status.
- CSV/PCAP replay.
- AI inference.
- Danh sách cảnh báo.
- Chi tiết cảnh báo.
- Thống kê lưu lượng.
- Thống kê loại tấn công.
- Beaconing candidates.
- Network graph.
- Model performance.
- Export cảnh báo CSV.

Sử dụng WebSocket để truyền cảnh báo và thống kê realtime đến frontend.

SQLite lưu:

- Monitoring sessions.
- Attack alerts.
- Beaconing candidates.
- System events.

Yêu cầu:

- Pydantic validation.
- Parameterized SQL.
- Pagination và filtering.
- Error handling.
- Structured logging.
- Background worker và bounded queue phù hợp.
- Không chạy inference trực tiếp trong packet callback.
- Không block FastAPI event loop.
- Không tạo capture worker trùng lặp.
- Graceful shutdown.
- API mặc định bind localhost.
- Không lưu packet payload mặc định.
- Không public control API ra Internet.

Phân biệt rõ dữ liệu LIVE, PCAP_REPLAY và CSV_REPLAY.

## 11. Phase 5 — React Dashboard

Xây dựng giao diện Web NIDS hiện đại, chuyên nghiệp, phong cách Cybersecurity Operations Center.

UI/UX:

- Dark theme.
- Sidebar navigation.
- Typography dễ đọc.
- Màu cyan hoặc blue làm chủ đạo.
- Màu đỏ cho cảnh báo ATTACK.
- Màu amber cho anomaly.
- Màu xanh cho trạng thái bình thường.
- Responsive trên desktop và laptop.
- Loading, empty, error và disconnected states.
- Không lạm dụng hiệu ứng neon hoặc animation.

### Trang 1 — Overview

Hiển thị:

- Tổng số packet và flow.
- Tổng số inference.
- Tổng số cảnh báo.
- Tỷ lệ BENIGN/ATTACK.
- Attack timeline.
- Attack distribution.
- Latest alerts.
- System status.
- Active model profile.
- Inference latency.

### Trang 2 — Live Monitoring

Cho phép:

- Chọn CIC-IDS2017 hoặc CIC-DDoS2019.
- Chọn network interface.
- Chọn nguồn LIVE, CSV hoặc PCAP.
- Start/stop monitoring.
- Theo dõi lưu lượng realtime.
- Hiển thị trạng thái BUFFERING nếu chưa đủ flow.
- Hiển thị cảnh báo ngay khi phát hiện.

Thông tin bảng realtime:

- Timestamp.
- Source IP.
- Destination IP.
- Protocol.
- Detection status.
- Predicted attack type.
- Model score.
- Latency.

### Trang 3 — Attack History

- Danh sách cảnh báo.
- Tìm kiếm.
- Lọc IP, thời gian, loại tấn công và profile.
- Chi tiết cảnh báo.
- Phân trang.
- Export CSV.

### Trang 4 — Beaconing & Network Graph

- Gaussian anomaly score.
- Suspected beaconing connections.
- Connection count.
- Mean interval.
- Standard deviation.
- Coefficient of variation.
- Đồ thị giao tiếp mạng.
- Node và edge details.
- Các node có dấu hiệu bất thường.

### Trang 5 — Model Performance

Đọc kết quả trực tiếp từ artifact đã export.

Hiển thị riêng cho từng dataset:

- Accuracy.
- Precision.
- Recall.
- F1-score.
- False Positive Rate nếu có.
- Confusion Matrix.
- Per-class performance.
- Model comparison đã thực hiện trên Colab.
- Pipeline comparison đã có.

Không chạy lại huấn luyện hoặc thực nghiệm để tạo dữ liệu cho trang này.

Phân biệt rõ Binary Accuracy và Multiclass Accuracy.

Không hiển thị 99.69% của CIC-DDoS2019 như độ chính xác phân loại 17 lớp hoặc độ chính xác realtime.

Frontend phải sử dụng API thật. Không sử dụng mock data để giả lập hệ thống đang hoạt động.

## 12. Phase 6 — Kiểm thử và triển khai trên Kali Linux

### Kiểm thử phần mềm

Viết unit test và integration test cho:

- Model loading.
- Preprocessing.
- Feature mapping.
- Inference.
- Label mapping.
- Gaussian scoring.
- Flow extraction.
- Temporal window.
- Detection engine.
- Database.
- FastAPI.
- WebSocket.

Chạy frontend typecheck và production build.

### Kiểm thử AI

- CSV replay bằng flow thật.
- PCAP replay bằng dữ liệu hợp lệ.
- So sánh preprocessing với Colab nếu có fixture.
- Kiểm tra output shape.
- Kiểm tra predicted label.
- Kiểm tra feature compatibility.
- Đo inference latency P50 và P95.

Không sử dụng dữ liệu giả để chứng minh độ chính xác mô hình.

### Kiểm thử mạng thực tế

Chuẩn bị kế hoạch kiểm thử trong môi trường Lab được cấp phép và cách ly:

1. Lưu lượng mạng bình thường.
2. Lưu lượng PortScan với CIC-IDS2017.
3. Lưu lượng DoS/DDoS có nhãn.
4. SYN traffic kiểm thử.
5. Kết nối định kỳ mô phỏng Beaconing.
6. Kết nối định kỳ hợp lệ để kiểm tra false positive.

Ưu tiên sử dụng PCAP có nhãn hoặc kịch bản mô phỏng an toàn.

Không tự động thực hiện tấn công, flood hoặc quét mạng bên ngoài môi trường được cấp phép.

Đo lường:

- Inference latency.
- End-to-end detection latency.
- Attack Recall.
- False Positive Rate.
- Throughput.
- Dropped packet count.
- Tỷ lệ flow đủ điều kiện inference.

Chỉ tính Accuracy, Recall, Precision và FPR khi có ground truth.

Không loại bỏ các trường hợp BUFFERING khỏi báo cáo coverage mà không giải thích.

### Tài liệu triển khai

Tạo README.md và docs/DEPLOYMENT.md hướng dẫn:

- Cài đặt trên Windows.
- Khởi chạy backend.
- Khởi chạy frontend.
- Import model artifact.
- Chạy CSV replay.
- Chạy PCAP replay.
- Cài đặt môi trường Kali Linux.
- Cấu hình quyền packet capture tối thiểu.
- Chọn network interface.
- Khởi chạy realtime monitoring.
- Kiểm thử và dừng hệ thống an toàn.

Không tự ý thay đổi firewall hoặc cấu hình mạng hệ điều hành.

## 13. Quy trình thực thi

Thực hiện theo thứ tự:

1. Kiểm tra workspace và artifact.
2. Hoàn thành AI Inference Engine.
3. Hoàn thành Packet Capture và Flow Extraction.
4. Hoàn thành Detection Engine.
5. Hoàn thành FastAPI và SQLite.
6. Hoàn thành React Dashboard.
7. Kiểm thử và chuẩn bị triển khai Kali Linux.

Kiểm thử từng phase trước khi chuyển sang phase tiếp theo.

Sau mỗi phase, báo cáo ngắn gọn:

- Công việc đã hoàn thành.
- File đã tạo hoặc chỉnh sửa.
- Kết quả test thực tế.
- Blocker nếu có.
- Công việc tiếp theo.

Không overengineering.

Không thay đổi hoặc xóa artifact gốc.

Không tự ý commit hoặc push Git.

Chỉ chỉnh sửa source code trong workspace hiện tại.

Tên class, function và variable bằng tiếng Anh. Comment tiếng Việt tại các logic AI và Network Security quan trọng.

Nếu thiếu artifact hoặc fixture, ghi rõ blocker và tiếp tục các phần độc lập có thể hoàn thành.

## 14. Definition of Done

Sản phẩm cần đạt các điều kiện:

- Hai profile CNN-LSTM load thành công.
- Preprocessing đúng với artifact.
- Inference hoạt động.
- CSV replay hoạt động.
- PCAP processing hoạt động.
- Feature extraction được kiểm chứng.
- Temporal window hoạt động đúng.
- Có cảnh báo và lịch sử cảnh báo.
- Gaussian score hoạt động.
- Beaconing heuristic hoạt động.
- Network graph hoạt động.
- FastAPI và SQLite hoạt động.
- React Dashboard kết nối API thật.
- WebSocket truyền cảnh báo realtime.
- Unit test và integration test đạt yêu cầu.
- Frontend production build thành công.
- Có tài liệu triển khai Kali Linux.
- Có kế hoạch và kết quả kiểm thử thực tế khi môi trường Lab sẵn sàng.

Chỉ đánh dấu realtime detection đã được xác thực sau khi thực sự kiểm thử trên Linux.

Nếu môi trường hiện tại là Windows, sử dụng trạng thái READY FOR LINUX VALIDATION cho các chức năng chưa thể kiểm chứng trực tiếp.

## FINAL INSTRUCTION

Bắt đầu ngay bằng việc kiểm tra các artifact đã import trong workspace.

Sau đó trực tiếp triển khai Phase 1 và tiếp tục các phase theo thứ tự phụ thuộc.

Không quay lại các giai đoạn nghiên cứu, EDA hoặc huấn luyện mô hình.

Mục tiêu là hoàn thành một sản phẩm NIDS sử dụng CNN-LSTM thật, tận dụng hai bộ trọng số đã huấn luyện, có Web Dashboard và khả năng triển khai giám sát mạng trên Kali Linux theo yêu cầu Giai đoạn 4 của giảng viên.