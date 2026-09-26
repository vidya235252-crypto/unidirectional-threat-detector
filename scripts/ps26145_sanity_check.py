"""SIH 26145 runtime sanity check.

Run from the repository root:
    python scripts/ps26145_sanity_check.py

This intentionally validates the production scenario entry points instead of
duplicating detector logic. It checks that every required threat class can
produce an alert from the current scenario fixtures and that the benign
fixture does not produce a threat alert.

The throughput target is the documented 30 flows/sec end-to-end target for
the flow-streaming orchestrator. This script measures the current fixtures
on the machine where it is run; it does not invent a benchmark result.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.config import SCENARIOS_DIR
from app.pipeline.orchestrator import (
    stream_scenario,
    stream_dns_scenario,
    stream_tls_scenario,
)

TARGET_FPS = 30.0

FLOW_EXPECTATIONS = {
    "benign": None,
    "port_scan": "PORT_SCAN",
    "syn_flood": "SYN_FLOOD",
    "c2_beaconing": "C2_BEACONING",
    "data_exfiltration": "DATA_EXFILTRATION",
}

SECONDARY_EXPECTATIONS = {
    "dga_dns_tunneling": "DGA_DNS_TUNNELING",
    "malicious_tls": "MALICIOUS_TLS",
}


def check_flow_scenario(name: str, expected: str | None) -> tuple[int, int, float]:
    started = time.perf_counter()
    flows = 0
    alerts = 0
    classes: set[str] = set()

    for _flow, _fv, alert in stream_scenario(SCENARIOS_DIR / f"{name}.jsonl"):
        flows += 1
        if alert is not None:
            alerts += 1
            classes.add(alert.threat_class)

    elapsed = max(time.perf_counter() - started, 1e-9)
    fps = flows / elapsed

    if expected is None:
        assert alerts == 0, f"{name}: expected 0 alerts, got {alerts}"
    else:
        assert expected in classes, (
            f"{name}: expected {expected}, observed {sorted(classes)}"
        )

    return flows, alerts, fps


def check_secondary_scenario(name: str, expected: str) -> tuple[int, int]:
    records = 0
    alerts = 0
    classes: set[str] = set()

    iterator = (
        stream_dns_scenario(SCENARIOS_DIR / f"{name}.jsonl")
        if name == "dga_dns_tunneling"
        else stream_tls_scenario(SCENARIOS_DIR / f"{name}.jsonl")
    )

    for _record, alert in iterator:
        records += 1
        if alert is not None:
            alerts += 1
            classes.add(alert.threat_class)

    assert expected in classes, (
        f"{name}: expected {expected}, observed {sorted(classes)}"
    )
    return records, alerts


def main() -> None:
    print("SIH 26145 scenario sanity check")
    print("=" * 36)

    flow_total = 0
    flow_elapsed = 0.0

    for name, expected in FLOW_EXPECTATIONS.items():
        flows, alerts, fps = check_flow_scenario(name, expected)
        flow_total += flows
        flow_elapsed += flows / fps
        result = "PASS"
        print(f"[{result}] {name:18s} flows={flows:5d} alerts={alerts:4d} rate={fps:8.1f} flows/s")

    for name, expected in SECONDARY_EXPECTATIONS.items():
        records, alerts = check_secondary_scenario(name, expected)
        print(f"[PASS] {name:18s} records={records:5d} alerts={alerts:4d}")

    aggregate_fps = flow_total / max(flow_elapsed, 1e-9)
    print("-" * 36)
    print(f"Flow-stream aggregate: {aggregate_fps:.1f} flows/s")
    print(f"Throughput target:      {TARGET_FPS:.1f} flows/s")

    assert aggregate_fps >= TARGET_FPS, (
        f"Throughput target missed: {aggregate_fps:.1f} < {TARGET_FPS:.1f} flows/s"
    )

    print("ALL SIH 26145 CHECKS PASSED")


if __name__ == "__main__":
    main()
