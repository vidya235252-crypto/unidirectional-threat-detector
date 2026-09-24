import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.contracts.feature_vector import Protocol
from app.core.feature_engine import FeatureEngine
from app.core.flow_engine import Flow
from app.core.packet_event import PacketEvent
from app.inference.inference_client import classify
from data_exfilteration_logic import PerIPTracker, classify_outbound_behavior


SAMPLE_SIZE = 3000


def build_flow(row: pd.Series, index: int) -> Flow:
    duration_us = max(float(row["Flow Duration"]), 1.0)
    first = pd.Timestamp("2026-09-24T00:00:00Z").to_pydatetime()
    last = first + pd.Timedelta(microseconds=duration_us).to_pytimedelta()

    packet_count = max(int(row["Total Fwd Packets"]), 1)
    packet_size = max(
        int(round(float(row["Total Length of Fwd Packets"]) / packet_count)),
        1,
    )

    src_ip = f"10.0.{index // 254}.{index % 254 + 1}"
    dst_ip = f"93.184.{index // 254}.{index % 254 + 1}"

    packets = [
        PacketEvent(
            timestamp=first,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=40000 + (index % 1000),
            dst_port=int(row["Destination Port"]),
            protocol=Protocol.TCP,
            packet_size=packet_size,
            syn_flag=(i == 0),
        )
        for i in range(packet_count)
    ]

    flow = Flow(
        flow_key=packets[0].flow_key(),
        first_seen=first,
        last_seen=last,
        packets=packets,
    )
    return flow


def run() -> None:
    df = pd.read_csv("data/processed/cleaned_network_data_rf.csv")

    _, test_df = train_test_split(
        df,
        test_size=0.15,
        stratify=df["Attack Type"],
        random_state=42,
    )
    _, test_df = train_test_split(
        test_df,
        test_size=0.5,
        stratify=test_df["Attack Type"],
        random_state=42,
    )
    test_df = test_df.iloc[:SAMPLE_SIZE].reset_index(drop=True)

    feature_engine = FeatureEngine()
    exfil_tracker = PerIPTracker()

    # Warm up the same production functions used below.
    for i in range(min(50, len(test_df))):
        flow = build_flow(test_df.iloc[i], i)
        fv = feature_engine.compute_incremental(flow)
        signal = classify_outbound_behavior(
            exfil_tracker,
            flow.src_ip,
            pd.Timestamp(fv.timestamp).timestamp(),
            fv.byte_count,
            fv.flow_duration,
            fv.packets_per_second,
            flow.dst_ip,
        )
        if not signal["alert_triggered"]:
            classify(fv)

    # Do not include warm-up state in the measured run.
    feature_engine = FeatureEngine()
    exfil_tracker = PerIPTracker()

    latencies = []
    alerts = 0

    for i, (_, row) in enumerate(test_df.iterrows()):
        flow = build_flow(row, i)

        t0 = time.perf_counter()

        fv = feature_engine.compute_incremental(flow)
        exfil_signal = classify_outbound_behavior(
            exfil_tracker,
            flow.src_ip,
            pd.Timestamp(fv.timestamp).timestamp(),
            fv.byte_count,
            fv.flow_duration,
            fv.packets_per_second,
            flow.dst_ip,
        )

        if exfil_signal["alert_triggered"]:
            alerts += 1
        else:
            response = classify(fv)
            if response.threat_class.value != "BENIGN":
                alerts += 1

        latencies.append(time.perf_counter() - t0)

    arr = np.asarray(latencies)
    total_time = arr.sum()

    print(
        f"END-TO-END STREAMING: "
        f"p50={np.percentile(arr, 50) * 1e3:.3f}ms  "
        f"p95={np.percentile(arr, 95) * 1e3:.3f}ms  "
        f"p99={np.percentile(arr, 99) * 1e3:.3f}ms  "
        f"throughput={len(arr) / total_time:.1f} flows/sec"
    )
    print(f"Flows processed: {len(arr)}")
    print(f"Alerts produced: {alerts}")


if __name__ == "__main__":
    run()
