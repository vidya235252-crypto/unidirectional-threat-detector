import asyncio
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.core import config
from app.db import database
from app.pipeline.orchestrator import run_scenario_full
from app.api.ws_manager import manager

router = APIRouter()

SCENARIO_NAMES = ["benign", "port_scan", "syn_flood", "c2_beaconing"]

_current_task: Optional[asyncio.Task] = None
_current_scenario: Optional[str] = None


class ScenarioStartRequest(BaseModel):
    scenario: str


def _scenario_path(name: str) -> Path:
    return config.SCENARIOS_DIR / f"{name}.jsonl"


def _alert_to_dict(alert) -> dict:
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "flow_id": alert.flow_id,
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
    pairs, alerts = run_scenario_full(path)

    for flow, fv in pairs:
        database.insert_flow(
            flow_id=fv.flow_id,
            timestamp=fv.timestamp,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.flow_key[2],
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            duration=fv.flow_duration,
            packet_count=fv.packet_count,
            byte_count=fv.byte_count,
        )

    await manager.broadcast({"type": "scenario_started", "scenario": name})

    for alert in alerts:
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
        await manager.broadcast({"type": "alert", "alert": _alert_to_dict(alert)})
        await asyncio.sleep(config.SCENARIO_STREAM_DELAY_SECONDS)

    await manager.broadcast({"type": "scenario_complete", "scenario": name})
    _current_scenario = None


@router.post("/api/scenario/start")
async def start_scenario(request: ScenarioStartRequest):
    global _current_task, _current_scenario

    if request.scenario not in SCENARIO_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{request.scenario}'")

    if _current_task is not None and not _current_task.done():
        raise HTTPException(status_code=409, detail=f"Scenario '{_current_scenario}' already running")

    _current_scenario = request.scenario
    _current_task = asyncio.create_task(_stream_scenario(request.scenario))
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
def get_alerts():
    return database.list_alerts()


@router.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = database.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/api/stats")
def get_stats():
    stats = database.get_stats()
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