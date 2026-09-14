from pathlib import Path
from typing import List, Tuple

from app.ingestion.scenario_loader import ScenarioLoader
from app.core.flow_engine import Flow, FlowEngine
from app.core.feature_engine import FeatureEngine
from app.core.config import FEATURE_WINDOW_SECONDS, ALERT_DEDUP_WINDOW_SECONDS
from app.contracts.feature_vector import FeatureVector
from app.inference.mock_inference import classify
from app.core.alert_engine import AlertEngine, Alert
from app.core.dedup import Deduplicator


def _run_pipeline(scenario_path: Path) -> List[Tuple[Flow, FeatureVector]]:
    loader = ScenarioLoader(scenario_path)
    flow_engine = FlowEngine()
    feature_engine = FeatureEngine()

    closed_flows: List[Flow] = []

    for packet in loader.load():
        flow_engine.process_packet(packet)
        stale = flow_engine.get_stale_flows(packet.timestamp, FEATURE_WINDOW_SECONDS)
        closed_flows.extend(stale)

    closed_flows.extend(flow_engine.flush_all())

    vectors = feature_engine.compute_batch(closed_flows)

    return list(zip(closed_flows, vectors))


def run_scenario(scenario_path: Path) -> List[FeatureVector]:
    pairs = _run_pipeline(scenario_path)
    return [vector for _, vector in pairs]


def run_scenario_with_alerts(scenario_path: Path) -> List[Alert]:
    pairs = _run_pipeline(scenario_path)

    alert_engine = AlertEngine()
    dedup = Deduplicator(window_seconds=ALERT_DEDUP_WINDOW_SECONDS)

    for flow, fv in pairs:
        response = classify(fv)

        if response.threat_class.value == "BENIGN":
            continue

        if dedup.should_suppress(flow.src_ip, response.threat_class.value):
            continue

        alert_engine.process(fv, response)

    return alert_engine.all_alerts()