import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))

from app.pipeline.orchestrator import stream_scenario


SCENARIOS = [
    "benign",
    "port_scan",
    "syn_flood",
    "c2_beaconing",
    "data_exfiltration",
]

REPETITIONS = 100


def benchmark_scenario(name: str) -> tuple[int, float]:
    path = ROOT / "data" / "scenarios" / f"{name}.jsonl"

    flow_count = 0
    start = time.perf_counter()

    for _ in range(REPETITIONS):
        for _flow, _fv, _alert in stream_scenario(path):
            flow_count += 1

    elapsed = time.perf_counter() - start
    return flow_count, elapsed


def run() -> None:
    latencies = []
    total_flows = 0

    print("END-TO-END STREAMING BENCHMARK")
    print("-" * 60)

    for name in SCENARIOS:
        path = ROOT / "data" / "scenarios" / f"{name}.jsonl"

        # Warm-up
        for _ in stream_scenario(path):
            pass

        start = time.perf_counter()
        flow_count = 0

        for _ in range(REPETITIONS):
            for _flow, _fv, _alert in stream_scenario(path):
                flow_count += 1

        elapsed = time.perf_counter() - start
        throughput = flow_count / elapsed

        latencies.append(elapsed)
        total_flows += flow_count

        print(
            f"{name:20s} "
            f"flows={flow_count:5d}  "
            f"time={elapsed:.4f}s  "
            f"throughput={throughput:.1f} flows/sec"
        )

    arr = np.asarray(latencies)

    print("-" * 60)
    print(f"Total flows processed: {total_flows}")
    print(f"Total benchmark time:  {arr.sum():.4f}s")
    print(
        f"Aggregate throughput:   "
        f"{total_flows / arr.sum():.1f} flows/sec"
    )


if __name__ == "__main__":
    run()