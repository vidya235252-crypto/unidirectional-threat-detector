import time
import random
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from data_exfilteration_logic import PerIPTracker, classify_outbound_behavior

# -----------------------------------------------------------------
# 1. Reuse the same held-out test split as RF/IF
# -----------------------------------------------------------------
df = pd.read_csv("data/processed/cleaned_network_data_rf.csv")
_, test_df = train_test_split(df, test_size=0.15, stratify=df["Attack Type"], random_state=42)
_, test_df = train_test_split(test_df, test_size=0.5, stratify=test_df["Attack Type"], random_state=42)

BEHAVIORAL_SAMPLE_SIZE = 5000
test_df = test_df.iloc[:BEHAVIORAL_SAMPLE_SIZE]

byte_counts = test_df["Total Length of Fwd Packets"].to_numpy(dtype=np.float64)
flow_durations_sec = test_df["Flow Duration"].to_numpy(dtype=np.float64) / 1e6   # µs -> s
pps_values = test_df["Fwd Packets/s"].to_numpy(dtype=np.float64)

# -----------------------------------------------------------------
# 2. Assign rows to fake IPs in BLOCKS (not per-row random) so each
#    entity gets enough consecutive flows to cross MIN_FLOWS_FOR_BASELINE
#    (10) and actually exercise the SCORED path, not just cold-start.
# -----------------------------------------------------------------
FAKE_IPS = [f"10.0.{i}.{random.randint(1,254)}" for i in range(20)]
BLOCK_SIZE = 25

entity_ids = []
for i in range(len(byte_counts)):
    block_index = i // BLOCK_SIZE
    entity_ids.append(FAKE_IPS[block_index % len(FAKE_IPS)])

dest_ips = [f"93.184.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(len(byte_counts))]
base_time = time.time()

# -----------------------------------------------------------------
# 3. Warm-up
# -----------------------------------------------------------------
tracker = PerIPTracker()
for i in range(100):
    classify_outbound_behavior(
        tracker, entity_ids[i], base_time + i * 0.001,
        byte_counts[i], flow_durations_sec[i], pps_values[i], dest_ips[i],
    )

# reset tracker so warm-up calls don't pollute the timed baseline state
tracker = PerIPTracker()

# -----------------------------------------------------------------
# 4. Timed loop
# -----------------------------------------------------------------
behavioral_latencies = []
scored_count, cold_start_count = 0, 0

for i in range(len(byte_counts)):
    t0 = time.perf_counter()
    result = classify_outbound_behavior(
        tracker, entity_ids[i], base_time + i * 0.001,
        byte_counts[i], flow_durations_sec[i], pps_values[i], dest_ips[i],
    )
    behavioral_latencies.append(time.perf_counter() - t0)

    if result["metrics"]["baseline_drift"]["status"] == "SCORED":
        scored_count += 1
    else:
        cold_start_count += 1

# -----------------------------------------------------------------
# 5. Report
# -----------------------------------------------------------------
def report(name, latencies):
    arr = np.array(latencies)
    print(f"{name}: p50={np.percentile(arr,50)*1e6:.1f}µs  "
          f"p95={np.percentile(arr,95)*1e6:.1f}µs  "
          f"p99={np.percentile(arr,99)*1e6:.1f}µs  "
          f"throughput={len(arr)/arr.sum():.1f} flows/sec")

report("Behavioral/Exfil", behavioral_latencies)
print(f"  (scored={scored_count}, cold_start={cold_start_count} — "
      f"confirms both code paths were exercised)")