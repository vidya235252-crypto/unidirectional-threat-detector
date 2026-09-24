import sys
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from datetime import datetime

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from app.ingestion.scenario_loader import ScenarioLoader

from app.ingestion.scenario_loader import ScenarioLoader
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
DnsStreamItem = Tuple[DnsQueryRecord, Optional[Alert]]
TlsStreamItem = Tuple[TlsSessionRecord, Optional[Alert]]


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
                confidence=1.0,
                anomaly_score=1.0,
                top_features=["outbound_behavior"],
                model_version="exfil-behavior-v1",
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
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = DnsQueryRecord.from_json_line(line)
            alert = classify_dns_record(
                record.domain, record.query_type, record.timestamp, record.src_ip
            )
            yield record, alert


def stream_tls_scenario(scenario_path: Path) -> Iterator[TlsStreamItem]:
    with open(scenario_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = TlsSessionRecord.from_json_line(line)
            alert = classify_tls_record(
                record.fingerprint, record.transport, record.role,
                record.timestamp, record.src_ip,
            )
            yield record, alert
