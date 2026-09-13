from pathlib import Path
from typing import List

from app.ingestion.scenario_loader import ScenarioLoader
from app.core.flow_engine import FlowEngine
from app.core.feature_engine import FeatureEngine
from app.core.config import FEATURE_WINDOW_SECONDS
from app.contracts.feature_vector import FeatureVector


def run_scenario(scenario_path: Path) -> List[FeatureVector]:
    loader = ScenarioLoader(scenario_path)
    flow_engine = FlowEngine()
    feature_engine = FeatureEngine()

    closed_flows = []

    for packet in loader.load():
        flow_engine.process_packet(packet)
        stale = flow_engine.get_stale_flows(packet.timestamp, FEATURE_WINDOW_SECONDS)
        closed_flows.extend(stale)

    closed_flows.extend(flow_engine.flush_all())

    vectors = feature_engine.compute_batch(closed_flows)

    return vectors