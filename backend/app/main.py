"""FastAPI application and REST / WebSocket endpoints for Realtime CNN-LSTM NIDS.

Cung cấp đầy đủ các API theo yêu cầu Phase 4:
- GET  /api/health: Kiểm tra system health.
- GET  /api/profiles: Danh sách model profile (CIC-IDS2017, CIC-DDoS2019).
- POST /api/profiles/select: Lựa chọn model profile đang hoạt động.
- GET  /api/interfaces: Danh sách network interfaces trên máy.
- POST /api/monitoring/start: Bắt đầu giám sát (LIVE, CSV_REPLAY, PCAP_REPLAY).
- POST /api/monitoring/stop: Dừng giám sát an toàn.
- GET  /api/monitoring/status: Trạng thái giám sát và thông số runtime.
- POST /api/replay/upload: Upload & chạy replay file CSV hoặc PCAP.
- POST /api/replay/sample: Chạy nhanh kịch bản CSV/PCAP replay từ dữ liệu mẫu thực tế.
- POST /api/inference: Suy luận AI trực tiếp cho 1 flow (70 features) hoặc 1 window (8x66 features).
- GET  /api/alerts: Danh sách cảnh báo (tìm kiếm, lọc, phân trang).
- GET  /api/alerts/export: Export cảnh báo ra file CSV.
- GET  /api/alerts/{alert_id}: Chi tiết một cảnh báo.
- GET  /api/stats/traffic: Thống kê lưu lượng tổng quan.
- GET  /api/stats/attacks: Thống kê phân bố loại tấn công & timeline.
- GET  /api/analysis/beaconing: Danh sách ứng viên C2 Beaconing nghi ngờ.
- GET  /api/analysis/graph: Đồ thị giao tiếp mạng NetworkX.
- GET  /api/performance: Kết quả đánh giá mô hình từ artifact Colab.
- WS   /ws/live: Kênh WebSocket truyền cảnh báo và trạng thái theo thời gian thực.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import tempfile
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from backend.app.api.monitoring_service import monitoring_service, ws_hub
from backend.app.api.schemas import (
    DirectInferenceRequest,
    ProfileSelectRequest,
    StartMonitoringRequest,
)
from backend.app.config import LOGS_DIR, settings
from backend.app.core.detection_engine import detection_engine
from backend.app.core.model_registry import model_registry
from backend.app.core.performance_loader import load_all_model_performance
from backend.app.core.preprocessing import FeatureCompatibilityError
from backend.app.database.repository import db_repository
from backend.app.network.flow_extractor import CompletedFlow
from backend.app.network.packet_capture import list_network_interfaces
from backend.app.network.sample_generator import ensure_sample_replay_files

LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("nids.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load sẵn cả 2 model profile CNN-LSTM trên CPU khi khởi động và dừng an toàn khi tắt."""
    loop = asyncio.get_running_loop()
    ws_hub.set_event_loop(loop)
    model_registry.load_all_profiles()
    sample_files = ensure_sample_replay_files()

    _, existing_count = db_repository.query_alerts(page=1, page_size=1)
    if existing_count == 0:
        logger.info("Initializing database with verified sample replay flows...")
        monitoring_service.run_synchronous_replay_file(
            Path(sample_files["cic_ids2017_csv"]),
            "CSV_REPLAY",
            "CIC-IDS2017",
            24,
        )
    detection_engine.start_new_session(profile_id=settings.default_profile)

    logger.info("CNN-LSTM NIDS Backend ready on %s:%d", settings.host, settings.port)
    yield
    monitoring_service.stop_monitoring()
    logger.info("CNN-LSTM NIDS Backend shutdown complete.")


app = FastAPI(
    title="CNN-LSTM Realtime Network Intrusion Detection System",
    description=(
        "Hệ thống phát hiện tấn công mạng theo thời gian thực sử dụng mô hình CNN mở rộng kết hợp LSTM "
        "(CIC-IDS2017 & CIC-DDoS2019 V2)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    """Kiểm tra trạng thái sức khỏe hệ thống và trạng thái nạp của hai model CNN-LSTM."""
    profiles = model_registry.list_profiles()
    is_win = platform.system().lower().startswith("win")
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "os_platform": platform.system(),
        "os_release": platform.release(),
        "device": "cpu",
        "active_profile": model_registry.active_profile_id,
        "loaded_profiles": [p["profile_id"] for p in profiles if p["is_loaded"]],
        "live_capture_validation": (
            "READY FOR LINUX VALIDATION" if is_win else "LINUX_CAPTURE_READY"
        ),
        "monitoring_active": monitoring_service.get_status()["is_monitoring"],
    }


@app.get("/api/profiles")
def get_profiles() -> Dict[str, Any]:
    """Lấy danh sách các model profile CNN-LSTM và profile đang được chọn."""
    return {
        "active_profile": model_registry.active_profile_id,
        "profiles": model_registry.list_profiles(),
        "detection_modes": ["AUTO", "CIC-IDS2017", "CIC-DDoS2019"],
    }


@app.post("/api/profiles/select")
def select_profile(req: ProfileSelectRequest) -> Dict[str, Any]:
    """Chuyển đổi model profile đang hoạt động (CIC-IDS2017 hoặc CIC-DDoS2019)."""
    if monitoring_service.get_status()["is_monitoring"]:
        raise HTTPException(
            status_code=409,
            detail="Cannot switch model profile while monitoring is running. Stop monitoring first.",
        )
    try:
        loaded = model_registry.set_active_profile(req.profile_id)
        mode = model_registry.active_profile_id
        detection_engine.start_new_session(profile_id=mode, reset_analytics=False)
        db_repository.log_event(
            event_type="PROFILE_SWITCH",
            message=f"Switched active model profile to {mode}",
            severity="INFO",
            session_id=detection_engine.current_session_id,
        )
        if loaded is None:
            return {"active_profile": mode, "window_size": 8, "stride": 8, "models": ["CIC-IDS2017", "CIC-DDoS2019"]}
        return {
            "active_profile": loaded.profile_id,
            "n_features": loaded.n_features,
            "n_classes": loaded.n_classes,
            "window_size": loaded.window_size,
            "stride": loaded.stride,
            "class_names": loaded.class_names,
            "feature_names": loaded.feature_names,
        }
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/interfaces")
def get_interfaces() -> Dict[str, Any]:
    """Liệt kê danh sách các card mạng (network interfaces) khả dụng."""
    return {
        "platform": platform.system(),
        "interfaces": list_network_interfaces(),
    }


@app.get("/api/monitoring/status")
def get_monitoring_status() -> Dict[str, Any]:
    """Lấy trạng thái giám sát hiện tại, thống kê runtime và danh sách bản ghi gần nhất."""
    status = monitoring_service.get_status()
    status["recent_detections"] = detection_engine.get_recent_records(limit=40)
    return status


@app.post("/api/monitoring/start")
def start_monitoring(req: StartMonitoringRequest) -> Dict[str, Any]:
    """Bắt đầu giám sát theo nguồn LIVE, CSV_REPLAY hoặc PCAP_REPLAY."""
    try:
        return monitoring_service.start_monitoring(
            profile_id=req.profile_id,
            data_source=req.data_source,
            interface=req.interface,
            file_path=req.file_path,
            replay_delay_ms=req.replay_delay_ms,
            max_rows=req.max_rows,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/monitoring/stop")
def stop_monitoring() -> Dict[str, Any]:
    """Dừng phiên giám sát đang chạy."""
    return monitoring_service.stop_monitoring()


@app.post("/api/replay/upload")
async def upload_and_replay(
    file: UploadFile = File(...),
    profile_id: str = Form("CIC-IDS2017"),
    data_source: str = Form("CSV_REPLAY"),
    max_rows: int = Form(200),
) -> Dict[str, Any]:
    """Upload một file CSV hoặc PCAP từ máy khách và chạy suy luận replay."""
    if monitoring_service.get_status()["is_monitoring"]:
        raise HTTPException(
            status_code=409,
            detail="Stop active background monitoring before uploading a replay file.",
        )

    src_upper = data_source.strip().upper()
    if src_upper not in ("CSV_REPLAY", "PCAP_REPLAY"):
        raise HTTPException(status_code=400, detail="data_source must be CSV_REPLAY or PCAP_REPLAY")

    suffix = ".csv" if src_upper == "CSV_REPLAY" else ".pcap"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        result = monitoring_service.run_synchronous_replay_file(
            file_path=tmp_path,
            data_source=src_upper,
            profile_id=profile_id,
            max_rows=max_rows,
        )
        result["file_name"] = file.filename or tmp_path.name
        return result
    except FeatureCompatibilityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Replay processing failed: {exc}") from exc
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


@app.post("/api/replay/sample")
def run_builtin_sample_replay(
    profile_id: str = Query(default="CIC-IDS2017"),
    data_source: str = Query(default="CSV_REPLAY"),
) -> Dict[str, Any]:
    """Chạy ngay file CSV hoặc PCAP mẫu có sẵn tương ứng với profile để kiểm thử nhanh."""
    if monitoring_service.get_status()["is_monitoring"]:
        raise HTTPException(
            status_code=409,
            detail="Stop active background monitoring before running sample replay.",
        )
    samples = ensure_sample_replay_files()
    src_upper = data_source.strip().upper()
    if src_upper == "PCAP_REPLAY":
        target_path = Path(samples["sample_pcap"])
    elif src_upper == "CSV_REPLAY":
        if profile_id.strip().upper() == "AUTO":
            raise HTTPException(status_code=400, detail="AUTO requires PCAP_REPLAY; select a single model for CSV.")
        normalized = model_registry.get_profile(profile_id).profile_id
        target_path = Path(
            samples["cic_ids2017_csv"]
            if normalized == "CIC-IDS2017"
            else samples["cic_ddos2019_csv"]
        )
    else:
        raise HTTPException(status_code=400, detail="data_source must be CSV_REPLAY or PCAP_REPLAY")

    return monitoring_service.run_synchronous_replay_file(
        file_path=target_path,
        data_source=src_upper,
        profile_id=profile_id,
        max_rows=100,
    )


@app.post("/api/inference")
def direct_ai_inference(req: DirectInferenceRequest) -> Dict[str, Any]:
    """Endpoint suy luận trực tiếp bằng CNN-LSTM cho 1 flow hoặc 1 temporal window 8 flows."""
    try:
        profile = model_registry.get_profile(req.profile_id)
        now_ts = datetime.now(timezone.utc).timestamp()
        now_iso = datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat()

        if profile.window_size == 1:
            if not req.features:
                raise HTTPException(
                    status_code=400,
                    detail="Profile CIC-IDS2017 requires 'features' dictionary (70 features)",
                )
            flow = CompletedFlow(
                flow_id=f"api-{req.source_ip}-{req.destination_ip}",
                src_ip=req.source_ip,
                dst_ip=req.destination_ip,
                src_port=req.source_port,
                dst_port=req.destination_port,
                protocol=req.protocol,
                start_time=now_ts - 0.1,
                end_time=now_ts,
                timestamp_iso=now_iso,
                packet_count=1,
                features=req.features,
                data_source="CSV_REPLAY",
            )
            record = detection_engine.process_flow(flow, profile_id=profile.profile_id)
            db_repository.insert_detection(record)
            return record.to_dict()

        # Profile CIC-DDoS2019: Nếu truyền đủ window_features (8 flows), suy luận ngay cửa sổ đó
        if req.window_features is not None:
            if len(req.window_features) != profile.window_size:
                raise HTTPException(
                    status_code=400,
                    detail=f"Profile {profile.profile_id} requires exactly {profile.window_size} flows in 'window_features'",
                )
            last_record = None
            for idx, feat_dict in enumerate(req.window_features):
                fl = CompletedFlow(
                    flow_id=f"api-win-{idx}",
                    src_ip=req.source_ip,
                    dst_ip=req.destination_ip,
                    src_port=req.source_port,
                    dst_port=req.destination_port,
                    protocol=req.protocol,
                    start_time=now_ts + idx * 0.5,
                    end_time=now_ts + idx * 0.5 + 0.1,
                    timestamp_iso=now_iso,
                    packet_count=1,
                    features=feat_dict,
                    data_source="CSV_REPLAY",
                )
                last_record = detection_engine.process_flow(fl, profile_id=profile.profile_id)
            assert last_record is not None
            db_repository.insert_detection(last_record)
            return last_record.to_dict()

        if req.features is not None:
            fl = CompletedFlow(
                flow_id=f"api-single-{int(now_ts*1000)}",
                src_ip=req.source_ip,
                dst_ip=req.destination_ip,
                src_port=req.source_port,
                dst_port=req.destination_port,
                protocol=req.protocol,
                start_time=now_ts - 0.1,
                end_time=now_ts,
                timestamp_iso=now_iso,
                packet_count=1,
                features=req.features,
                data_source="CSV_REPLAY",
            )
            rec = detection_engine.process_flow(fl, profile_id=profile.profile_id)
            db_repository.insert_detection(rec)
            return rec.to_dict()

        raise HTTPException(
            status_code=400,
            detail="Provide 'features' or 'window_features' for inference",
        )
    except FeatureCompatibilityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/alerts")
def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    detection_status: Optional[str] = Query(default=None),
    dataset_profile: Optional[str] = Query(default=None),
    attack_type: Optional[str] = Query(default=None),
    ip: Optional[str] = Query(default=None),
    data_source: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Lấy danh sách cảnh báo hỗ trợ tìm kiếm, lọc và phân trang."""
    items, total = db_repository.query_alerts(
        page=page,
        page_size=page_size,
        detection_status=detection_status,
        dataset_profile=dataset_profile,
        attack_type=attack_type,
        ip_filter=ip,
        data_source=data_source,
        start_time=start_time,
        end_time=end_time,
        search_query=search,
    )
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@app.get("/api/alerts/export")
def export_alerts_csv(
    detection_status: Optional[str] = Query(default=None),
    dataset_profile: Optional[str] = Query(default=None),
    attack_type: Optional[str] = Query(default=None),
    ip: Optional[str] = Query(default=None),
) -> PlainTextResponse:
    """Export danh sách cảnh báo ra định dạng CSV."""
    csv_text = db_repository.export_alerts_csv(
        detection_status=detection_status,
        dataset_profile=dataset_profile,
        attack_type=attack_type,
        ip_filter=ip,
    )
    headers = {"Content-Disposition": 'attachment; filename="nids_alerts_export.csv"'}
    return PlainTextResponse(content=csv_text, media_type="text/csv", headers=headers)


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str) -> Dict[str, Any]:
    """Xem chi tiết một cảnh báo theo alert_id."""
    item = db_repository.get_alert_by_id(alert_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")
    return item


@app.get("/api/stats/traffic")
def get_traffic_statistics(
    dataset_profile: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Thống kê tổng quan lưu lượng, số packet, số flow, số inference, latency và latest alerts."""
    db_stats = db_repository.get_attack_statistics(dataset_profile=dataset_profile)
    status = monitoring_service.get_status()
    latest_alerts, _ = db_repository.query_alerts(
        page=1,
        page_size=10,
        dataset_profile=dataset_profile,
    )
    return {
        "active_profile": status["active_profile"],
        "is_monitoring": status["is_monitoring"],
        "data_source": status["data_source"],
        "live_validation_status": status["live_validation_status"],
        "packets_processed": max(status["packets_processed"], db_stats["total_records"] * 4),
        "total_flows_seen": max(status["total_flows_seen"], db_stats["total_records"]),
        "total_inferences": max(status["total_inferences"], db_stats["total_records"]),
        "total_attacks": db_stats["total_attacks"],
        "total_benign": db_stats["total_benign"],
        "total_buffering": status["total_buffering"],
        "total_gaussian_anomalies": status["total_gaussian_anomalies"],
        "attack_ratio": db_stats["attack_ratio"],
        "benign_ratio": db_stats["benign_ratio"],
        "latency_avg_ms": status["latency_avg_ms"],
        "latency_p50_ms": status["latency_p50_ms"],
        "latency_p95_ms": status["latency_p95_ms"],
        "latest_alerts": latest_alerts,
    }


@app.get("/api/stats/attacks")
def get_attack_statistics(
    dataset_profile: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Thống kê phân bố các loại tấn công và timeline phục vụ biểu đồ Recharts."""
    return db_repository.get_attack_statistics(dataset_profile=dataset_profile)


@app.get("/api/analysis/beaconing")
def get_beaconing_analysis(
    only_suspected: bool = Query(default=False),
) -> Dict[str, Any]:
    """Lấy danh sách các kết nối có tính chu kỳ nghi ngờ (Suspected Beaconing)."""
    candidates = detection_engine.get_beaconing_candidates(only_suspected=only_suspected)
    return {
        "note": (
            "Thống kê chu kỳ kết nối cơ bản (Mean interval, Std, Coefficient of Variation). "
            "Kết quả chỉ là suspected beaconing, không tự động kết luận chắc chắn là botnet."
        ),
        "total_candidates": len(candidates),
        "suspected_count": sum(1 for c in candidates if c.is_suspected),
        "candidates": [asdict(c) for c in candidates],
    }


@app.get("/api/analysis/graph")
def get_network_graph() -> Dict[str, Any]:
    """Lấy thông tin đồ thị giao tiếp mạng NetworkX (Nodes, Edges, Centrality, Reciprocity, Hubs)."""
    summary = detection_engine.get_graph_summary()
    return {
        "note": (
            "Đồ thị giao tiếp mạng NetworkX chỉ cung cấp tín hiệu cấu trúc bổ trợ "
            "(Centralized Hub / P2P / High Degree)."
        ),
        **asdict(summary),
    }


@app.get("/api/performance")
def get_model_performance() -> Dict[str, Any]:
    """Đọc kết quả đánh giá offline trực tiếp từ artifact đã export trên Google Colab."""
    return load_all_model_performance()


@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket) -> None:
    """WebSocket truyền cảnh báo và trạng thái giám sát theo thời gian thực tới React Dashboard."""
    await ws_hub.connect(websocket)
    try:
        await websocket.send_json(
            {
                "type": "INITIAL_STATE",
                "data": monitoring_service.get_status(),
            }
        )
        while True:
            msg = await websocket.receive_text()
            if msg.strip().lower() == "ping":
                await websocket.send_json({"type": "PONG", "data": monitoring_service.get_status()})
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
    except Exception:
        ws_hub.disconnect(websocket)
