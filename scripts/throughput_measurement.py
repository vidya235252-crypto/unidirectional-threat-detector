import pandas as pd
import numpy as np
import joblib
import json
import time
import uuid
import random
import warnings
from sklearn.model_selection import train_test_split
from preprocessing_utils import log1p_transform

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# --- toggle for fast local debugging vs the real report run ---
DEBUG = False        # set True only while testing the pipeline quickly
DEBUG_SAMPLE_SIZE = 2000
SINGLE_FLOW_SAMPLE_SIZE = 3000   # enough for stable p50/p95/p99, runs in ~1 min instead of ~1hr

# 1. Held-out test split — real one, must match training script's split call
df = pd.read_csv("data/processed/cleaned_network_data_rf.csv")
_, test_df = train_test_split(df, test_size=0.15, stratify=df["Attack Type"], random_state=42)
_, test_df = train_test_split(test_df, test_size=0.5, stratify=test_df["Attack Type"], random_state=42)

# 2. Frozen 10-field schema
FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Flow Bytes/s", "Fwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std",
    "Fwd Packet Length Mean", "Fwd Packet Length Min",
]

feature_matrix = test_df[FEATURE_COLS].to_numpy(dtype=np.float64)
labels = test_df["Attack Type"].to_numpy()

if DEBUG:
    feature_matrix = feature_matrix[:DEBUG_SAMPLE_SIZE]
    labels = labels[:DEBUG_SAMPLE_SIZE]

# 3. FlowRecords — fake IPs for now, real ones come from live flow engine later
FAKE_IP_POOL = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]

class FlowRecord:
    __slots__ = ("feature_vector", "flow_meta")
    def __init__(self, feature_vector, source_ip, dest_ip, timestamp, flow_id):
        self.feature_vector = feature_vector
        self.flow_meta = {"source_ip": source_ip, "dest_ip": dest_ip,
                           "timestamp": timestamp, "flow_id": flow_id}

records = [
    FlowRecord(feature_matrix[i], random.choice(FAKE_IP_POOL), random.choice(FAKE_IP_POOL),
               time.time() + i * 0.001, str(uuid.uuid4()))
    for i in range(len(feature_matrix))
]

# 4. Load models + calibrated threshold (loaded once each)
rf_model = joblib.load("models/random_forest_model.joblib")
rf_model.n_jobs = 1

if_model = joblib.load("models/optimized_isolation_forest.joblib")
if_model.n_jobs = 1

with open("models/optimized_isolation_forest_threshold.json") as f:
    threshold_data = json.load(f)
if_threshold = threshold_data["calibrated_threshold"]

# 5. Warm-up
for r in records[:100]:
    v = r.feature_vector.reshape(1, -1)
    rf_model.predict(v)
    if_model.score_samples(log1p_transform(v, FEATURE_COLS))

# 6a. TRUE single-flow latency — sampled, not the full set (full set = ~1hr, unnecessary)
rf_latencies_single, if_latencies_single = [], []
for r in records[:SINGLE_FLOW_SAMPLE_SIZE]:
    v = r.feature_vector.reshape(1, -1)

    t0 = time.perf_counter()
    rf_model.predict(v)
    rf_latencies_single.append(time.perf_counter() - t0)

    t0 = time.perf_counter()
    if_score = if_model.score_samples(log1p_transform(v, FEATURE_COLS))[0]
    if_latencies_single.append(time.perf_counter() - t0)
    if_flag = if_score <= if_threshold

# 6b. MICRO-BATCHED — unchanged, still runs on the FULL feature_matrix

# 6b. MICRO-BATCHED throughput — buffer BATCH_SIZE flows, predict once per batch
BATCH_SIZE = 50
rf_batch_times, if_batch_times = [], []

for start in range(0, len(feature_matrix), BATCH_SIZE):
    batch = feature_matrix[start:start + BATCH_SIZE]
    if len(batch) == 0:
        continue

    t0 = time.perf_counter()
    rf_model.predict(batch)
    rf_batch_times.append((time.perf_counter() - t0, len(batch)))

    t0 = time.perf_counter()
    if_model.score_samples(log1p_transform(batch, FEATURE_COLS))
    if_batch_times.append((time.perf_counter() - t0, len(batch)))

# 7. Report
def report_single(name, latencies):
    arr = np.array(latencies)
    print(f"[single-flow] {name}: p50={np.percentile(arr,50)*1e6:.1f}µs  "
          f"p95={np.percentile(arr,95)*1e6:.1f}µs  "
          f"p99={np.percentile(arr,99)*1e6:.1f}µs  "
          f"throughput={len(arr)/arr.sum():.1f} flows/sec")

def report_batched(name, batch_times):
    total_time = sum(t for t, n in batch_times)
    total_rows = sum(n for t, n in batch_times)
    per_row = [t / n for t, n in batch_times]
    print(f"[batched x{BATCH_SIZE}] {name}: per-row p50={np.percentile(per_row,50)*1e6:.1f}µs  "
          f"per-row p99={np.percentile(per_row,99)*1e6:.1f}µs  "
          f"throughput={total_rows/total_time:.1f} flows/sec")

report_single("RF", rf_latencies_single)
report_single("IForest", if_latencies_single)
report_batched("RF", rf_batch_times)
report_batched("IForest", if_batch_times)