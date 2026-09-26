import asyncio
import time
from collections import deque
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.core import config
from app.db import database
from app.pipeline.orchestrator import stream_scenario, stream_dns_scenario, stream_tls_scenario
from app.api.ws_manager import manager

router = APIRouter()

FLOW_SCENARIOS = ["benign", "port_scan", "syn_flood", "c2_beaconing", "data_exfiltration"]
DNS_SCENARIOS = ["dga_dns_tunneling"]
TLS_SCENARIOS = ["malicious_tls"]
SCENARIO_NAMES = FLOW_SCENARIOS + DNS_SCENARIOS + TLS_SCENARIOS

_current_task: Optional[asyncio.Task] = None
_current_scenario: Optional[str] = None
_flow_times: deque[float] = deque()
_detection_latencies: deque[float] = deque(maxlen=100)

def _record_flow() -> None:
    now = time.monotonic()
    _flow_times.append(now)
    cutoff = now - 5.0
    while _flow_times and _flow_times[0] < cutoff:
        _flow_times.popleft()

def _record_detection_latency(started: float) -> None:
    _detection_latencies.append((time.perf_counter() - started) * 1000)

def _runtime_telemetry() -> dict:
    now = time.monotonic()
    cutoff = now - 5.0
    while _flow_times and _flow_times[0] < cutoff:
        _flow_times.popleft()
    throughput = len(_flow_times) / 5.0
    latency = (
        sum(_detection_latencies) / len(_detection_latencies)
        if _detection_latencies
        else 0.0
    )
    return {
        "throughput_fps": round(throughput, 1),
        "detection_latency_ms": round(latency, 1),
    }


class ScenarioStartRequest(BaseModel):
    scenario: str


def _scenario_path(name: str) -> Path:
    return config.SCENARIOS_DIR / f"{name}.jsonl"


def _alert_to_dict(alert) -> dict:
    flow = database.get_flow(alert.flow_id) or {}
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "flow_id": alert.flow_id,
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip") or None,
        "src_port": flow.get("src_port") or None,
        "dst_port": flow.get("dst_port") or None,
        "protocol": flow.get("protocol"),
        "threat_class": alert.threat_class,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "anomaly_score": alert.anomaly_score,
        "evidence": alert.evidence,
        "model_version": alert.model_version,
    }


async def _stream_scenario(name: str) -> None:
    global _current_scenario
    path = _scenario_path(name)

    await manager.broadcast({"type": "scenario_started", "scenario": name})

    try:
        iterator = iter(stream_scenario(path))
        while True:
            started = time.perf_counter()
            try:
                flow, fv, alert = next(iterator)
            except StopIteration:
                break

            _record_detection_latency(started)
            _record_flow()

            database.insert_flow(
                flow_id=fv.flow_id,
                timestamp=fv.timestamp,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                duration=fv.flow_duration,
                packet_count=fv.packet_count,
                byte_count=fv.byte_count,
            )

            if alert is not None:
                database.insert_alert(
                    alert_id=alert.alert_id,
                    timestamp=alert.timestamp,
                    flow_id=alert.flow_id,
                    threat_class=alert.threat_class,
                    severity=alert.severity,
                    confidence=alert.confidence,
                    anomaly_score=alert.anomaly_score,
                    evidence=alert.evidence,
                    model_version=alert.model_version,
                )
                await manager.broadcast({"type": "alert", "scenario": name, "alert": _alert_to_dict(alert)})
                await asyncio.sleep(config.SCENARIO_STREAM_DELAY_SECONDS)

    except FileNotFoundError as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"detector data missing: {exc}"})
        return
    except Exception as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"scenario failed: {type(exc).__name__}: {exc}"})
        return
    finally:
        _current_scenario = None

    await manager.broadcast({"type": "scenario_complete", "scenario": name})


def _insert_metadata_flow(flow_id: str, timestamp: str, src_ip: str, protocol: str, dst_port: int) -> None:
    database.insert_flow(
        flow_id=flow_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="",
        src_port=0,
        dst_port=dst_port,
        protocol=protocol,
        duration=0.0,
        packet_count=1,
        byte_count=0,
    )


async def _emit_alert(alert, scenario: str) -> None:
    database.insert_alert(
        alert_id=alert.alert_id,
        timestamp=alert.timestamp,
        flow_id=alert.flow_id,
        threat_class=alert.threat_class,
        severity=alert.severity,
        confidence=alert.confidence,
        anomaly_score=alert.anomaly_score,
        evidence=alert.evidence,
        model_version=alert.model_version,
    )
    await manager.broadcast({"type": "alert", "scenario": scenario, "alert": _alert_to_dict(alert)})
    await asyncio.sleep(config.SCENARIO_STREAM_DELAY_SECONDS)


async def _stream_dns_scenario(name: str) -> None:
    global _current_scenario
    path = _scenario_path(name)

    await manager.broadcast({"type": "scenario_started", "scenario": name})
    try:
        iterator = iter(stream_dns_scenario(path))
        while True:
            started = time.perf_counter()
            try:
                _record, alert = next(iterator)
            except StopIteration:
                break
            _record_detection_latency(started)
            _record_flow()
            _insert_metadata_flow(
                _record.flow_id,
                _record.timestamp,
                _record.src_ip,
                "DNS",
                53,
            )
            if alert is not None:
                await _emit_alert(alert, name)
    except FileNotFoundError as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"detector data missing: {exc}"})
        return
    except Exception as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"scenario failed: {type(exc).__name__}: {exc}"})
        return
    finally:
        _current_scenario = None
    await manager.broadcast({"type": "scenario_complete", "scenario": name})


async def _stream_tls_scenario(name: str) -> None:
    global _current_scenario
    path = _scenario_path(name)

    await manager.broadcast({"type": "scenario_started", "scenario": name})
    try:
        iterator = iter(stream_tls_scenario(path))
        while True:
            started = time.perf_counter()
            try:
                _record, alert = next(iterator)
            except StopIteration:
                break
            _record_detection_latency(started)
            _record_flow()
            _insert_metadata_flow(
                _record.flow_id,
                _record.timestamp,
                _record.src_ip,
                "TLS",
                443,
            )
            if alert is not None:
                await _emit_alert(alert, name)
    except FileNotFoundError as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"detector data missing: {exc}"})
        return
    except Exception as exc:
        await manager.broadcast({"type": "error", "scenario": name, "message": f"scenario failed: {type(exc).__name__}: {exc}"})
        return
    finally:
        _current_scenario = None
    await manager.broadcast({"type": "scenario_complete", "scenario": name})


def _run_scenario_task(name: str) -> asyncio.Task:
    if name in DNS_SCENARIOS:
        return asyncio.create_task(_stream_dns_scenario(name))
    if name in TLS_SCENARIOS:
        return asyncio.create_task(_stream_tls_scenario(name))
    return asyncio.create_task(_stream_scenario(name))


@router.post("/api/scenario/start")
async def start_scenario(request: ScenarioStartRequest):
    global _current_task, _current_scenario

    if request.scenario not in SCENARIO_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{request.scenario}'")

    if _current_task is not None and not _current_task.done():
        raise HTTPException(status_code=409, detail=f"Scenario '{_current_scenario}' already running")

    _current_scenario = request.scenario
    _current_task = _run_scenario_task(request.scenario)
    return {"status": "started", "scenario": request.scenario}


@router.post("/api/scenario/stop")
async def stop_scenario():
    global _current_task, _current_scenario

    if _current_task is None or _current_task.done():
        return {"status": "not_running"}

    stopped_scenario = _current_scenario
    _current_task.cancel()
    try:
        await _current_task
    except asyncio.CancelledError:
        pass
    _current_task = None
    _current_scenario = None
    await manager.broadcast({"type": "scenario_stopped", "scenario": stopped_scenario})
    return {"status": "stopped", "scenario": stopped_scenario}


@router.get("/api/alerts")
def get_alerts(limit: Optional[int] = None):
    return database.list_alerts(limit=limit)


@router.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = database.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/api/stats")
def get_stats():
    stats = database.get_stats()
    stats.update(_runtime_telemetry())
    stats["running"] = _current_task is not None and not _current_task.done()
    stats["current_scenario"] = _current_scenario
    return stats


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)