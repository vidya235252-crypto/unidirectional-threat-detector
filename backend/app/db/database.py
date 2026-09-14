import json
import sqlite3
from typing import Optional

from app.core.config import DB_PATH

_connection: Optional[sqlite3.Connection] = None


def get_connection() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
    return _connection


def init_db() -> None:
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS flows (
            flow_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            duration REAL NOT NULL,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            flow_id TEXT NOT NULL,
            threat_class TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            anomaly_score REAL NOT NULL,
            evidence TEXT NOT NULL,
            model_version TEXT NOT NULL
        )
        """
    )
    conn.commit()


def insert_flow(
    flow_id: str,
    timestamp: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    duration: float,
    packet_count: int,
    byte_count: int,
) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT OR REPLACE INTO flows
            (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, duration, packet_count, byte_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, duration, packet_count, byte_count),
    )
    conn.commit()


def insert_alert(
    alert_id: str,
    timestamp: str,
    flow_id: str,
    threat_class: str,
    severity: str,
    confidence: float,
    anomaly_score: float,
    evidence: dict,
    model_version: str,
) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts
            (alert_id, timestamp, flow_id, threat_class, severity, confidence, anomaly_score, evidence, model_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (alert_id, timestamp, flow_id, threat_class, severity, confidence, anomaly_score, json.dumps(evidence), model_version),
    )
    conn.commit()


def list_alerts() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
    return [_alert_row_to_dict(row) for row in rows]


def get_alert(alert_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return _alert_row_to_dict(row) if row else None


def get_stats() -> dict:
    conn = get_connection()
    total_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    by_class_rows = conn.execute(
        "SELECT threat_class, COUNT(*) as count FROM alerts GROUP BY threat_class"
    ).fetchall()
    by_severity_rows = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
    ).fetchall()
    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "alerts_by_class": {row["threat_class"]: row["count"] for row in by_class_rows},
        "alerts_by_severity": {row["severity"]: row["count"] for row in by_severity_rows},
    }


def _alert_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"])
    return d


def reset_db() -> None:
    conn = get_connection()
    conn.execute("DELETE FROM flows")
    conn.execute("DELETE FROM alerts")
    conn.commit()