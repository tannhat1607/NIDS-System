# Hướng dẫn thực hiện 8 test case NIDS trên Kali Linux

Tài liệu dành cho giai đoạn kiểm thử hệ thống CNN-LSTM NIDS sau khi đã cài đặt backend, frontend và hai model profile. Xem [DEPLOYMENT.md](DEPLOYMENT.md) để biết cách cài đặt ban đầu.

## 1. Chuẩn bị môi trường

Thực hiện toàn bộ trên máy Kali của bạn. Các kịch bản PortScan, DoS/DDoS và Syn sử dụng CSV/PCAP offline có sẵn, không phát gói tin tấn công lên mạng. LIVE chỉ sử dụng lưu lượng HTTP thông thường trên loopback hoặc mạng lab thuộc quyền quản lý của bạn.

**Terminal 1 — Backend**

```bash
cd ~/NIDS-System
source .venv/bin/activate
bash scripts/start_kali.sh
```

Nếu backend đã chạy, giữ nguyên terminal đó. Dòng `Application startup complete` và `Uvicorn running on http://127.0.0.1:8000` cho biết quá trình khởi động thành công. `GET /` hoặc `/favicon.ico` trả 404 là bình thường vì FastAPI không khai báo các route này.

**Terminal 2 — Frontend**

```bash
cd ~/NIDS-System/frontend
npm run build
npm run preview -- --host 127.0.0.1 --port 4173
```

Nếu đã build thành công thì chỉ cần chạy lệnh preview. Cảnh báo bundle JavaScript lớn hơn 500 kB không làm build thất bại.

Mở Firefox trên Kali tại `http://127.0.0.1:4173`. Swagger API tại `http://127.0.0.1:8000/docs`.

**Terminal 3 — Chuẩn bị dữ liệu và thực hiện kiểm thử**

```bash
cd ~/NIDS-System
source .venv/bin/activate
mkdir -p data/test-cases data/test-results
curl -fsS http://127.0.0.1:8000/api/health | python -m json.tool
curl -fsS http://127.0.0.1:4173/api/health | python -m json.tool
ls -lh data/samples/
```

Health check cần trả `status: healthy`, `device: cpu`, hai profile đã nạp. Trang Live Monitoring cần hiển thị WebSocket đã kết nối. Dữ liệu mặc định được backend tạo khi khởi động:

- `data/samples/cic_ids2017_sample_flows.csv`
- `data/samples/cic_ddos2019_temporal_sample_flows.csv`
- `data/samples/lab_mixed_traffic_sample.pcap`

Các CSV mẫu được tạo từ thống kê artifact, không phải dữ liệu gốc đã được gán nhãn thủ công. Giá trị `Label` là nhãn kỳ vọng của fixture. Đánh giá chất lượng mô hình cần thêm tập dữ liệu thật có nhãn độc lập.

Chạy một lần đoạn lệnh dưới đây để tách các CSV mẫu theo test case. Script chỉ đọc file mẫu và ghi file kiểm thử mới; không thay đổi các file nguồn. Nếu đã cấu hình `NIDS_DATA_DIR` khác mặc định, thay đường dẫn tương ứng.

```bash
python - <<'PY'
from pathlib import Path
import pandas as pd

samples = Path('data/samples')
out = Path('data/test-cases')
out.mkdir(parents=True, exist_ok=True)
ids = pd.read_csv(samples / 'cic_ids2017_sample_flows.csv')
ddos = pd.read_csv(samples / 'cic_ddos2019_temporal_sample_flows.csv')

def save(frame, name):
    assert not frame.empty, f'No rows for {name}'
    frame.to_csv(out / name, index=False)
    print(f'{name}: {len(frame)} flows')

save(ids[ids['Label'] == 'BENIGN'], 'tc01_benign.csv')
save(ids[ids['Label'] == 'PortScan'], 'tc02_portscan.csv')
save(ids[ids['Label'].isin(['DDoS', 'DoS Hulk'])], 'tc03_ids2017_dos.csv')
save(ddos[ddos['Label'] == 'DrDoS_DNS'], 'tc03_ddos2019_dns.csv')
save(ddos[ddos['Label'] == 'Syn'], 'tc04_syn.csv')

# Cùng một cặp IP với 6 flow BENIGN và các khoảng thời gian không đều.
irregular = ids[ids['Label'] == 'BENIGN'].iloc[:6].copy()
assert len(irregular) == 6
base = pd.Timestamp.now(tz='UTC').floor('s') - pd.Timedelta(seconds=110)
irregular['Source IP'] = '192.0.2.61'
irregular['Destination IP'] = '192.0.2.62'
irregular['Flow ID'] = [f'tc06-{i}' for i in range(6)]
irregular['Timestamp'] = [(base + pd.Timedelta(seconds=s)).isoformat()
                          for s in [0, 1, 16, 61, 63, 103]]
save(irregular, 'tc06_irregular.csv')
PY
```

### Quy trình chung cho các test replay

1. Dừng phiên giám sát đang chạy bằng **Stop Monitoring** trước mỗi test.
2. Mở trang **Live Monitoring**, chọn đúng Model Profile và Data Source trong từng TC.
3. Chọn file tương ứng, nhấn **Chạy File Upload**. Ghi lại kết quả xử lý và chụp màn hình bảng detection. Có thể dùng lệnh API ở từng TC thay cho thao tác upload để lưu bằng chứng JSON; không cần chạy cả hai vì sẽ tạo thêm bản ghi.
4. Đọc kết quả JSON bằng `python -m json.tool data/test-results/<ten-file>.json`. Các trường quan trọng gồm `session_id`, `flows_processed`, `inferences_completed`, `attack_count`, `benign_count`, `buffering_count` và `records`.

Các bộ đếm trên Overview và một phần Monitoring Status có thể tích lũy qua nhiều phiên. Đối chiếu theo `session_id` và kết quả replay riêng của từng TC. Để đo Beaconing TC05/TC06 chính xác, thực hiện lần đầu với cặp IP tương ứng trong phiên backend hiện tại. Nếu đã replay cặp IP đó trước đó, có thể dừng monitoring và khởi động lại backend để xóa lịch sử Beaconing trong bộ nhớ; SQLite vẫn giữ dữ liệu.

## 2. Danh sách test case

| ID | Nội dung | Profile | Nguồn |
|---|---|---|---|
| TC01 | Lưu lượng BENIGN | CIC-IDS2017 | CSV_REPLAY |
| TC02 | Nhận diện PortScan | CIC-IDS2017 | CSV_REPLAY |
| TC03 | Nhận diện DoS/DDoS | Cả hai profile | CSV_REPLAY |
| TC04 | Syn và cửa sổ temporal 8 flow | CIC-DDoS2019 | CSV_REPLAY |
| TC05 | PCAP Replay và Beaconing định kỳ | CIC-IDS2017 | PCAP_REPLAY |
| TC06 | Phân biệt kết nối không định kỳ | CIC-IDS2017 | CSV_REPLAY |
| TC07 | Bắt lưu lượng LIVE trên Kali | CIC-IDS2017 | LIVE |
| TC08 | Lịch sử, lưu SQLite và Export CSV | Cả hai profile | Dữ liệu các TC trước |

## TC01 — Lưu lượng bình thường (BENIGN baseline)

**Mục tiêu:** Kiểm tra phân loại flow đơn, nhãn BENIGN, độ trễ và false positive trên fixture bình thường.

**Thực hiện:** Chọn `CIC-IDS2017`, `CSV_REPLAY`, upload `data/test-cases/tc01_benign.csv`. Hoặc chạy:

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-IDS2017 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc01_benign.csv > data/test-results/tc01.json
```

**Kỳ vọng:** 6 flow, 6 inference, 0 BUFFERING. Mong muốn cả 6 được dự đoán BENIGN. Đối chiếu `ground_truth_label` với `predicted_attack_type`; xem `inference_latency_ms`, `gaussian_anomaly_score` và `gaussian_threshold`.

**Đánh giá:** Pipeline đạt nếu xử lý đủ 6 flow. Nếu dự đoán ATTACK, ghi false positive thực tế. FPR fixture = `attack_count / 6 × 100%`. Gaussian là tín hiệu bổ trợ, không tự quyết định ATTACK.

**Bằng chứng:** `tc01.json` và ảnh Live Monitoring thể hiện kết quả BENIGN/ATTACK thực tế.

## TC02 — Nhận diện PortScan bằng dữ liệu offline

**Mục tiêu:** Kiểm tra khả năng phân loại lớp PortScan của model CIC-IDS2017.

**Thực hiện:** Chọn `CIC-IDS2017`, `CSV_REPLAY`, upload `data/test-cases/tc02_portscan.csv`. Hoặc:

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-IDS2017 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc02_portscan.csv > data/test-results/tc02.json
```

**Kỳ vọng:** 6 flow, 6 inference, 0 BUFFERING. Nhãn kỳ vọng `PortScan`; dự đoán mong muốn là `ATTACK` với `predicted_attack_type: PortScan`.

**Đánh giá:** Phân biệt số flow dự đoán ATTACK và số flow dự đoán đúng PortScan. Ghi lại mọi nhãn sai thay vì sửa dữ liệu đầu vào để ép mô hình dự đoán đúng.

**Bằng chứng:** `tc02.json`, ảnh Live Monitoring và Attack History lọc theo IP nguồn `172.16.0.2`.

## TC03 — Nhận diện DoS/DDoS trên hai model profile

**Mục tiêu:** So sánh cơ chế suy luận từng flow của CIC-IDS2017 với suy luận cửa sổ temporal của CIC-DDoS2019.

**Thực hiện:** Chạy lần lượt hai file CSV, mỗi file chọn đúng profile. Kết thúc phiên trước khi chuyển profile.

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-IDS2017 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc03_ids2017_dos.csv > data/test-results/tc03_ids2017.json

curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-DDoS2019 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc03_ddos2019_dns.csv > data/test-results/tc03_ddos2019.json
```

**Kỳ vọng:** CIC-IDS2017 có 9 flow, 9 inference, 0 BUFFERING; nhãn kỳ vọng DDoS và DoS Hulk. CIC-DDoS2019 có 8 flow cùng IP nguồn, 7 BUFFERING và 1 inference, nhãn kỳ vọng DrDoS_DNS. Mong muốn các inference có trạng thái ATTACK và nhãn tương ứng.

**Đánh giá:** Kiểm tra số lượng inference độc lập với kết quả phân loại. Đối chiếu nhãn thật của fixture với dự đoán, ghi sai khác giữa các lớp DoS/DDoS.

**Bằng chứng:** Hai file JSON, ảnh bảng detection của hai profile và trang Model Performance (chỉ số offline từ artifact, tách riêng kết quả lab).

## TC04 — Syn và cửa sổ temporal 8 flow

**Mục tiêu:** Kiểm chứng cơ chế BUFFERING, window size 8, stride 8 và phân loại lớp Syn trên dữ liệu đặc trưng offline.

**Thực hiện:** Chọn `CIC-DDoS2019`, `CSV_REPLAY`, upload `data/test-cases/tc04_syn.csv`. Hoặc:

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-DDoS2019 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc04_syn.csv > data/test-results/tc04.json
```

**Kỳ vọng:** 8 flow có cùng Source IP và timestamp hợp lệ trong 300 giây. 7 bản ghi đầu `BUFFERING`, bản ghi thứ 8 `BENIGN` hoặc `ATTACK` với `required_window_size: 8`. Dự đoán mong muốn là ATTACK/Syn.

**Đánh giá:** `flows_processed = 8`, `buffering_count = 7`, `inferences_completed = 1`. Không có inference hoàn chỉnh ở 7 flow đầu. Nếu nhãn thứ 8 khác Syn, ghi nhận lỗi phân loại riêng.

**Bằng chứng:** `tc04.json` và ảnh thể hiện BUFFERING trước khi đủ cửa sổ. Có thể dùng `Start Monitoring` với CSV mẫu có sẵn và tăng Replay Delay để quan sát chuyển trạng thái trên WebSocket; file mẫu đầy đủ có 3 cửa sổ, khác với fixture 8 flow của TC04.

## TC05 — PCAP Replay và Beaconing định kỳ

**Mục tiêu:** Kiểm tra đọc PCAP offline, trích xuất flow, thống kê kết nối định kỳ và Network Graph.

**Thực hiện:** Trên Kali, gọi API interfaces trước để backend nạp các lớp giao thức Scapy. Sau đó chọn `CIC-IDS2017`, `PCAP_REPLAY`, upload `data/samples/lab_mixed_traffic_sample.pcap` hoặc dùng API replay dưới đây.

```bash
curl -fsS http://127.0.0.1:8000/api/interfaces > data/test-results/tc05_interfaces.json
curl -fsS -X POST \
  'http://127.0.0.1:8000/api/replay/sample?profile_id=CIC-IDS2017&data_source=PCAP_REPLAY' \
  > data/test-results/tc05.json
curl -fsS http://127.0.0.1:8000/api/analysis/beaconing \
  > data/test-results/tc05_beaconing.json
curl -fsS http://127.0.0.1:8000/api/analysis/graph \
  > data/test-results/tc05_graph.json
```

Mở trang **Beaconing & Graph**, tìm cặp `192.168.1.200` → `198.51.100.42`. Đây là địa chỉ trong dữ liệu mẫu, không phải máy đích cần kết nối thật.

**Kỳ vọng:** PCAP gốc được tạo với 40 packet và 16 flow (8 kết nối TCP định kỳ, 8 flow UDP). Với profile CIC-IDS2017, mỗi flow hoàn thành tạo 1 inference. Cặp TCP có 8 connections, mean interval xấp xỉ 5 giây, CV xấp xỉ 0 và `SUSPECTED_BEACONING`. Đồ thị có node/edge tương ứng. Kiểm tra ngay sau replay vì đồ thị có cơ chế giữ dữ liệu theo thời gian.

**Đánh giá:** Số flow và inference phù hợp dữ liệu đầu vào; Beaconing có ít nhất 5 kết nối và CV ≤ 0.25. PCAP mẫu không có ground-truth label, không dùng để kết luận accuracy. Beaconing định kỳ chỉ là tín hiệu nghi ngờ, kể cả với lưu lượng hợp lệ.

**Xử lý lỗi PCAP:** Nếu backend báo `unknown LL type [228]` hoặc đọc được 40 packet nhưng 0 flow, dừng phiên và khởi động lại backend với các lớp IP/TCP/UDP được nạp trước:

```bash
cd ~/NIDS-System
source .venv/bin/activate
python -c 'from scapy.layers.inet import IP, TCP, UDP; import uvicorn; uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000)'
```

Chờ startup complete rồi replay lại một lần. Khi kiểm tra offline trên môi trường phát triển, cùng file PCAP đã cho 40 packet và 16 flow sau khi nạp lớp IP. Nếu Kali vẫn trả 0 flow, ghi TC05 FAIL và lưu log thay vì xác nhận thành công.

**Bằng chứng:** Ba file JSON và ảnh Beaconing & Graph.

## TC06 — Kết nối không định kỳ

**Mục tiêu:** Kiểm tra bộ phân tích Beaconing phân biệt các khoảng thời gian không đều với trường hợp định kỳ.

**Thực hiện:** Chọn `CIC-IDS2017`, `CSV_REPLAY`, upload `data/test-cases/tc06_irregular.csv` hoặc:

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/replay/upload \
  -F profile_id=CIC-IDS2017 -F data_source=CSV_REPLAY \
  -F file=@data/test-cases/tc06_irregular.csv > data/test-results/tc06.json
curl -fsS 'http://127.0.0.1:8000/api/analysis/beaconing?only_suspected=false' \
  > data/test-results/tc06_beaconing.json
```

Mở **Beaconing & Graph**, bỏ chọn **Chỉ hiện Suspected Beaconing** và tìm cặp `192.0.2.61` → `192.0.2.62`.

**Kỳ vọng:** 6 kết nối, khoảng cách 1, 15, 45, 2, 40 giây, mean interval 20.6 giây, CV > 0.25, `IRREGULAR`, `is_suspected: false`. Khi bật bộ lọc chỉ hiện Suspected Beaconing, cặp này biến mất khỏi bảng.

**Đánh giá:** PASS nếu cặp IP có kết quả IRREGULAR và bộ lọc đúng. Nhãn CNN-LSTM là kết quả phân loại độc lập với Beaconing.

**Bằng chứng:** `tc06.json`, `tc06_beaconing.json`, ảnh trước và sau khi bật bộ lọc.

## TC07 — Live Capture thực tế trên Kali

**Mục tiêu:** Kiểm chứng Scapy bắt packet, trích xuất flow, CNN-LSTM inference và WebSocket trên môi trường Linux thật.

**Chuẩn bị:** Dừng replay. Trong Terminal 3, kiểm tra interface và trạng thái hiện tại:

```bash
ip -br addr show
curl -fsS http://127.0.0.1:8000/api/interfaces | python -m json.tool
curl -fsS http://127.0.0.1:8000/api/monitoring/status > data/test-results/tc07_before.json
```

Mở **Terminal 4**, tạo HTTP server thử nghiệm trên loopback. Chỉ phục vụ một thư mục tạm riêng, không phục vụ thư mục dự án.

```bash
LAB_DIR=$(mktemp -d)
printf 'NIDS local test\n' > "$LAB_DIR/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$LAB_DIR"
```

Trên Dashboard, chọn `CIC-IDS2017`, `LIVE`, interface `lo` (hoặc interface loopback thực tế theo API), nhấn **Start Monitoring**. Quay lại Terminal 3, thực hiện 3 HTTP request thông thường:

```bash
for i in 1 2 3; do
  curl -fsS http://127.0.0.1:8081/
  sleep 1
done
curl -fsS http://127.0.0.1:8000/api/monitoring/status > data/test-results/tc07_running.json
```

Kiểm tra Live Monitoring khi phiên đang chạy. Sau khi thấy flow HTTP hoàn thành, nhấn **Stop Monitoring**, rồi lưu trạng thái:

```bash
curl -fsS http://127.0.0.1:8000/api/monitoring/status > data/test-results/tc07_stopped.json
```

**Kỳ vọng:** Khi chạy, `is_monitoring: true`, `data_source: LIVE`, `interface: lo`, có flow HTTP tới cổng 8081, packet và inference tăng, WebSocket nhận bản ghi. Sau khi dừng, `is_monitoring: false`. Không yêu cầu đúng số packet/flow vì loopback còn mang lưu lượng của dashboard và API. BENIGN là nhãn mong muốn cho HTTP hợp lệ, nhưng model có thể dự đoán sai.

**Đánh giá:** PASS pipeline nếu có ít nhất một detection record LIVE đúng phiên, liên quan cổng 8081, và dừng được phiên. Nếu không bắt được packet, kiểm tra quyền capture, interface, backend log và `last_error`; xem phần 3.2 của [DEPLOYMENT.md](DEPLOYMENT.md) để xử lý quyền trên máy lab. Chỉ kết luận LIVE đã được xác thực khi thực sự quan sát được packet/flow; health check thành công chưa đủ. Nếu cần kiểm tra flow hết hạn, tiếp tục quan sát khi phiên còn chạy; mặc định flow timeout là 120 giây. Dừng HTTP server bằng Ctrl+C sau khi hoàn thành.

**Bằng chứng:** Ba file JSON, ảnh Live Monitoring khi đang chạy và sau khi dừng.

## TC08 — Lưu SQLite, tra cứu lịch sử và Export CSV

**Mục tiêu:** Kiểm tra kết quả inference được lưu, truy xuất theo profile/IP/trạng thái và tồn tại sau khi restart backend.

**Thực hiện:** Sau các test trên, mở **Attack History**. Chọn profile `CIC-IDS2017`, tìm IP `172.16.0.2` từ TC02, mở chi tiết một bản ghi. Thử lọc BENIGN/ATTACK theo kết quả thật, sau đó nhấn **Export CSV**.

```bash
curl -fsS 'http://127.0.0.1:8000/api/alerts?dataset_profile=CIC-IDS2017&ip=172.16.0.2&page_size=100' \
  > data/test-results/tc08_before.json
curl -fsS 'http://127.0.0.1:8000/api/alerts/export?dataset_profile=CIC-IDS2017&ip=172.16.0.2' \
  > data/test-results/tc08_export.csv
head -n 3 data/test-results/tc08_export.csv
```

Dừng monitoring nếu đang chạy. Nhấn Ctrl+C tại Terminal 1, khởi động lại bằng `bash scripts/start_kali.sh`, giữ frontend chạy. Sau khi backend báo startup complete, thực hiện:

```bash
curl -fsS 'http://127.0.0.1:8000/api/alerts?dataset_profile=CIC-IDS2017&ip=172.16.0.2&page_size=100' \
  > data/test-results/tc08_after.json
python - <<'PY'
import json
from pathlib import Path
p = Path('data/test-results')
before = json.loads((p / 'tc08_before.json').read_text())
after = json.loads((p / 'tc08_after.json').read_text())
old = {r['alert_id'] for r in before['items']}
new = {r['alert_id'] for r in after['items']}
assert old and old <= new, 'Records missing after restart'
print('PASS:', len(old), 'records retained after restart')
PY
```

**Kỳ vọng:** Bản ghi đã inference có `alert_id`, IP, predicted class, profile, data source, Gaussian score và latency. Dữ liệu có trước restart vẫn tồn tại trong SQLite (`data/nids.db` mặc định). CSV chứa header và các bản ghi phù hợp bộ lọc IP/profile. BUFFERING không được lưu vào bảng lịch sử inference. API export hiện hỗ trợ status, profile, attack type và IP; không hỗ trợ tất cả bộ lọc của bảng (ví dụ Data Source).

**Đánh giá:** PASS nếu truy vấn trả bản ghi đúng và script kiểm tra lưu trữ báo PASS. Không xóa database để làm sạch dữ liệu. Với hơn 100 bản ghi phù hợp IP, tăng `page_size` tối đa 200 hoặc phân trang để đối chiếu toàn bộ.

**Bằng chứng:** `tc08_before.json`, `tc08_after.json`, `tc08_export.csv`, ảnh bảng lịch sử và chi tiết bản ghi.

## 3. Tổng hợp kết quả thực nghiệm

Điền kết quả sau khi thực hiện trên Kali. Không đánh dấu PASS cho test chưa chạy.

| Test case | Kết quả thực tế (flow/inference/nhãn) | Pipeline PASS/FAIL | Phân loại đúng/sai (nếu có nhãn) | Minh chứng |
|---|---|---|---|---|
| TC01 | Chưa chạy | | | tc01.json |
| TC02 | Chưa chạy | | | tc02.json |
| TC03 | Chưa chạy | | | tc03_ids2017.json, tc03_ddos2019.json |
| TC04 | Chưa chạy | | | tc04.json |
| TC05 | Chưa chạy | | | tc05.json, tc05_beaconing.json, tc05_graph.json |
| TC06 | Chưa chạy | | | tc06.json, tc06_beaconing.json |
| TC07 | Chưa chạy | | | tc07_running.json, tc07_stopped.json |
| TC08 | Chưa chạy | | | tc08_before.json, tc08_after.json, tc08_export.csv |

Mỗi test phân loại nên ghi số mẫu có nhãn, số dự đoán đúng, false positive/false negative và latency. Với profile temporal, chỉ tính chất lượng phân loại trên inference hoàn chỉnh (cửa sổ), không tính BUFFERING như một lỗi phân loại. Các test có dữ liệu tổng hợp chỉ dùng để kiểm tra chức năng, không thay thế báo cáo accuracy/precision/recall trên tập kiểm thử độc lập.
