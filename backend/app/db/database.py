import json
import sqlite3
import threading
from functools import wraps
from typing import Optional

from app.core.config import DB_PATH

_connection: Optional[sqlite3.Connection] = None

# The connection above is shared across every request, but FastAPI runs sync
# route handlers in a thread pool. sqlite3 (even with check_same_thread=False)
# is not safe for concurrent statement execution on one connection from
# multiple threads at once - it can hand back a cursor whose column layout
# was clobbered by a concurrent query, causing intermittent IndexErrors on
# row["column"] access under load. This lock serializes all DB access.
_db_lock = threading.Lock()


def _synchronized(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with _db_lock:
            return fn(*args, **kwargs)
    return wrapper


def get_connection() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
    return _connection


@_synchronized
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


@_synchronized
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


@_synchronized
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


@_synchronized
def list_alerts(limit: Optional[int] = None) -> list[dict]:
    conn = get_connection()
    query = """
        SELECT a.*, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol
        FROM alerts a
        LEFT JOIN flows f ON f.flow_id = a.flow_id
        ORDER BY a.timestamp DESC
    """
    params = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)
    rows = conn.execute(query, params).fetchall()
    return [_alert_row_to_dict(row) for row in rows]


@_synchronized
def get_flow(flow_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM flows WHERE flow_id = ?", (flow_id,)).fetchone()
    return dict(row) if row else None


@_synchronized
def get_alert(alert_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        """
        SELECT a.*, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol
        FROM alerts a
        LEFT JOIN flows f ON f.flow_id = a.flow_id
        WHERE a.alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    return _alert_row_to_dict(row) if row else None


@_synchronized
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
    by_class_severity_rows = conn.execute(
        """
        SELECT threat_class, severity, COUNT(*) as count
        FROM alerts
        GROUP BY threat_class, severity
        """
    ).fetchall()

    alerts_by_class_severity: dict[str, dict[str, int]] = {}
    for row in by_class_severity_rows:
        alerts_by_class_severity.setdefault(row["threat_class"], {})[row["severity"]] = row["count"]

    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "alerts_by_class": {row["threat_class"]: row["count"] for row in by_class_rows},
        "alerts_by_severity": {row["severity"]: row["count"] for row in by_severity_rows},
        "alerts_by_class_severity": alerts_by_class_severity,
    }


def _alert_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"])
    return d


@_synchronized
def reset_db() -> None:
    conn = get_connection()
    conn.execute("DELETE FROM flows")
    conn.execute("DELETE FROM alerts")
    conn.commit()