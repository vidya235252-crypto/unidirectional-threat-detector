from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from app.ingestion.scenario_loader import ScenarioLoader
from app.core.flow_engine import Flow, FlowEngine
from app.core.feature_engine import FeatureEngine
from app.core.config import FEATURE_WINDOW_SECONDS, ALERT_DEDUP_WINDOW_SECONDS
from app.contracts.feature_vector import FeatureVector
from app.inference.inference_client import classify
from app.core.alert_engine import AlertEngine, Alert
from app.core.dedup import Deduplicator

StreamItem = Tuple[Flow, FeatureVector, Optional[Alert]]


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

    def _process(flow: Flow) -> StreamItem:
        fv = feature_engine.compute_incremental(flow)
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
