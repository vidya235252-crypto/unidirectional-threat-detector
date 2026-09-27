import random
import sys
import uuid
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from datetime import datetime, timedelta

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from app.ingestion.scenario_loader import ScenarioLoader
from app.core.packet_event import PacketEvent

from app.core.flow_engine import Flow, FlowEngine
from app.core.feature_engine import FeatureEngine
from app.core.config import FEATURE_WINDOW_SECONDS, ALERT_DEDUP_WINDOW_SECONDS
from app.contracts.feature_vector import FeatureVector
from app.inference.inference_client import classify
from app.core.alert_engine import AlertEngine, Alert
from app.core.dedup import Deduplicator

from app.contracts.dns_tls_events import DnsQueryRecord, TlsSessionRecord
from app.inference.secondary_detectors import classify_dns_record, classify_tls_record
from data_exfilteration_logic import PerIPTracker, classify_outbound_behavior
from app.contracts.inference_response import InferenceResponse, ThreatClass

StreamItem = Tuple[Flow, FeatureVector, Optional[Alert]]
DnsStreamItem = Tuple[DnsQueryRecord, Optional[Alert], str]
TlsStreamItem = Tuple[TlsSessionRecord, Optional[Alert], str]


def _jitter_timestamp(ts: str) -> str:
    """Shift a fixture's timestamp by a few random seconds so repeated demo
    runs of the same scenario don't show the identical instant every time."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ts
    dt = dt + timedelta(seconds=random.randint(-30, 30))
    return dt.isoformat().replace("+00:00", "Z")


def stream_scenario(scenario_path: Path) -> Iterator[StreamItem]:
    """True streaming pipeline: classifies and alerts on each flow the
    instant it closes (via inactivity timeout), not after the whole file
    has been read. For a continuous live feed this means bounded per-flow
    latency instead of waiting for end-of-stream."""
    loader = ScenarioLoader(scenario_path)
    flow_engine = FlowEngine()
    feature_engine = FeatureEngine()
    alert_engine = AlertEngine()
    dedup = Deduplicator(window_seconds=ALERT_DEDUP_WINDOW_SECONDS)
    exfil_tracker = PerIPTracker()

    # One consistent time offset + IP-octet shift per run, so repeated demo
    # runs show different absolute IPs/timestamps. On top of that, per-flow
    # multiplicative jitter (±15% on inter-packet gaps, ±10% on packet size)
    # so the DERIVED evidence (inter-arrival time, packets/sec, byte counts,
    # confidence, anomaly score) also varies run to run, not just cosmetics.
    # Order is always preserved and jitter is small enough to stay well
    # inside the class this fixture was built to trigger.
    run_time_offset = timedelta(seconds=random.randint(-600, 600))
    run_octet_shift = random.randint(0, 254)
    _last_orig_ts: dict = {}
    _last_adj_ts: dict = {}

    def _shift_ip(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        parts[3] = str((int(parts[3]) + run_octet_shift) % 256)
        return ".".join(parts)

    def _jitter_packet(packet: PacketEvent) -> PacketEvent:
        key = packet.flow_key()
        if key not in _last_orig_ts:
            new_ts = packet.timestamp + run_time_offset
        else:
            orig_delta = packet.timestamp - _last_orig_ts[key]
            jittered_delta = orig_delta * random.uniform(0.85, 1.15)
            new_ts = _last_adj_ts[key] + jittered_delta
        _last_orig_ts[key] = packet.timestamp
        _last_adj_ts[key] = new_ts

        jittered_size = max(1, round(packet.packet_size * random.uniform(0.9, 1.1)))

        return packet.model_copy(update={
            "timestamp": new_ts,
            "src_ip": _shift_ip(packet.src_ip),
            "dst_ip": _shift_ip(packet.dst_ip),
            "packet_size": jittered_size,
        })

    def _process(flow: Flow) -> StreamItem:
        fv = feature_engine.compute_incremental(flow)
        exfil_signal = classify_outbound_behavior(
            exfil_tracker,
            flow.src_ip,
            datetime.fromisoformat(fv.timestamp).timestamp(),
            fv.byte_count,
            fv.flow_duration,
            fv.packets_per_second,
            flow.dst_ip,
        )
        if exfil_signal["alert_triggered"]:
            response = InferenceResponse(
                flow_id=fv.flow_id,
                threat_class=ThreatClass.DATA_EXFILTRATION,
                confidence=0.0,
                anomaly_score=1.0,
                top_features=["outbound_behavior"],
                model_version="behavioral-exfil-v1",
            )
        else:
            response = classify(fv)

        alert: Optional[Alert] = None
        if response.threat_class.value != "BENIGN" and not dedup.should_suppress(
            flow.src_ip, response.threat_class.value
        ):
            alert = alert_engine.process(fv, response)

        return flow, fv, alert

    for packet in loader.load():
        packet = _jitter_packet(packet)
        flow_engine.process_packet(packet)
        for stale_flow in flow_engine.get_stale_flows(packet.timestamp, FEATURE_WINDOW_SECONDS):
            yield _process(stale_flow)

    for flow in flow_engine.flush_all():
        yield _process(flow)


def run_scenario(scenario_path: Path) -> List[FeatureVector]:
    return [fv for _, fv, _ in stream_scenario(scenario_path)]


def run_scenario_full(scenario_path: Path) -> Tuple[List[Tuple[Flow, FeatureVector]], List[Alert]]:
    pairs: List[Tuple[Flow, FeatureVector]] = []
    alerts: List[Alert] = []
    for flow, fv, alert in stream_scenario(scenario_path):
        pairs.append((flow, fv))
        if alert is not None:
            alerts.append(alert)
    return pairs, alerts


def run_scenario_with_alerts(scenario_path: Path) -> List[Alert]:
    _, alerts = run_scenario_full(scenario_path)
    return alerts


def stream_dns_scenario(scenario_path: Path) -> Iterator[DnsStreamItem]:
    with open(scenario_path, "r") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    # Replay a random, randomly-ordered subset each run instead of every line
    # in file order every time, so repeated demo runs don't look identical.
    random.shuffle(lines)
    if len(lines) > 1:
        lines = lines[: random.randint(1, len(lines))]
    for line in lines:
        record = DnsQueryRecord.from_json_line(line)
        # Jitter the timestamp slightly so repeated runs don't share the
        # exact same instant either.
        record.timestamp = _jitter_timestamp(record.timestamp)
        flow_id = f"dns_{uuid.uuid4().hex[:8]}"
        alert = classify_dns_record(
            record.domain, record.query_type, record.timestamp, record.src_ip,
            flow_id=flow_id,
        )
        yield record, alert, flow_id


def stream_tls_scenario(scenario_path: Path) -> Iterator[TlsStreamItem]:
    with open(scenario_path, "r") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    random.shuffle(lines)
    if len(lines) > 1:
        lines = lines[: random.randint(1, len(lines))]
    for line in lines:
        record = TlsSessionRecord.from_json_line(line)
        record.timestamp = _jitter_timestamp(record.timestamp)
        flow_id = f"tls_{uuid.uuid4().hex[:8]}"
        alert = classify_tls_record(
            record.fingerprint, record.transport, record.role,
            record.timestamp, record.src_ip,
            flow_id=flow_id,
        )
        yield record, alert, flow_id
