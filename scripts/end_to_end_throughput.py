import time
import random
import string
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from preprocessing_utils import log1p_transform
from detector_interfaces import classify_dns_query, classify_tls_session, BAMBENEK_PATH
from ja3_detector import BLOCKLIST_PATH as JA3_BLOCKLIST_PATH
from alert_fusion_engine import SecurityAlertEngine
import joblib

# -----------------------------------------------------------------
# 1. Small held-out sample, real schema, reused across all branches
# -----------------------------------------------------------------
FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Flow Bytes/s", "Fwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std",
    "Fwd Packet Length Mean", "Fwd Packet Length Min",
]

df = pd.read_csv("data/processed/cleaned_network_data_rf.csv")
_, test_df = train_test_split(df, test_size=0.15, stratify=df["Attack Type"], random_state=42)
_, test_df = train_test_split(test_df, test_size=0.5, stratify=test_df["Attack Type"], random_state=42)

E2E_SAMPLE_SIZE = 3000
test_df = test_df.iloc[:E2E_SAMPLE_SIZE]
feature_matrix = test_df[FEATURE_COLS].to_numpy(dtype=np.float64)
flow_durations_sec = test_df["Flow Duration"].to_numpy(dtype=np.float64) / 1e6
pps_values = test_df["Fwd Packets/s"].to_numpy(dtype=np.float64)
byte_counts = test_df["Total Length of Fwd Packets"].to_numpy(dtype=np.float64)

# -----------------------------------------------------------------
# 2. Fake IPs in blocks — same trick as behavioral script, so entities
#    build real baseline state across the run, not all cold-start
# -----------------------------------------------------------------
FAKE_IPS = [f"10.0.{i}.{random.randint(1,254)}" for i in range(20)]
BLOCK_SIZE = 25
source_ips = [FAKE_IPS[(i // BLOCK_SIZE) % len(FAKE_IPS)] for i in range(E2E_SAMPLE_SIZE)]
dest_ips = [f"93.184.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(E2E_SAMPLE_SIZE)]
flow_ids = [f"flow-{i}" for i in range(E2E_SAMPLE_SIZE)]
base_time = time.time()

# -----------------------------------------------------------------
# 3. DNS + JA3 sample data, mixing all branches (same as earlier scripts)
# -----------------------------------------------------------------
def load_bambenek_domains(path, n=100):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            d = line.split(",")[0].strip().lower()
            if d and "." in d:
                out.append(d)
            if len(out) >= n:
                break
    return out

def random_novel_domain():
    core = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 20)))
    return f"{core}.com"

def load_ja3_hashes(path, n=100):
    import csv
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = next(i for i, c in enumerate(header) if "ja3" in c.lower() or "hash" in c.lower())
        for row in reader:
            if row and row[idx].strip():
                out.append(row[idx].strip().lower())
            if len(out) >= n:
                break
    return out

def random_valid_ja3():
    return "".join(random.choices("0123456789abcdef", k=32))

domain_pool = load_bambenek_domains(BAMBENEK_PATH, 50) + \
              ["google.com", "wikipedia.org"] * 25 + \
              [random_novel_domain() for _ in range(50)]
ja3_pool = load_ja3_hashes(JA3_BLOCKLIST_PATH, 50) + [random_valid_ja3() for _ in range(50)]

domains = [random.choice(domain_pool) for _ in range(E2E_SAMPLE_SIZE)]
ja3_fps = [random.choice(ja3_pool) for _ in range(E2E_SAMPLE_SIZE)]

# -----------------------------------------------------------------
# 4. Load models + engine (engine owns its own IForest + tracker + window)
# -----------------------------------------------------------------
rf_model = joblib.load("models/random_forest_model.joblib")
rf_model.n_jobs = 1

engine = SecurityAlertEngine(
    iforest_model_path="models/optimized_isolation_forest.joblib",
    iforest_threshold_path="models/optimized_isolation_forest_threshold.json",
)

# Batch-predict RF once per BATCH — engine itself scores IForest per-call
# inside process_network_ml, so we only need RF's batched label here.
BATCH_SIZE = 50
rf_labels_all = []
for start in range(0, len(feature_matrix), BATCH_SIZE):
    batch = feature_matrix[start:start + BATCH_SIZE]
    rf_labels_all.extend(rf_model.predict(batch))

# Engine also needs the raw IForest score for "Bots" rows — batch that too.
if_model = joblib.load("models/optimized_isolation_forest.joblib")
if_model.n_jobs = 1
if_scores_all = []
for start in range(0, len(feature_matrix), BATCH_SIZE):
    batch = feature_matrix[start:start + BATCH_SIZE]
    if_scores_all.extend(if_model.score_samples(log1p_transform(batch, FEATURE_COLS)))

# -----------------------------------------------------------------
# 5. Warm-up (discard) — one full pass through everything once
# -----------------------------------------------------------------
for i in range(50):
    classify_dns_query(domains[i], "A", pd.Timestamp.utcnow().isoformat(), source_ips[i])
    classify_tls_session(ja3_fps[i], "tls", "client", pd.Timestamp.utcnow().isoformat(), source_ips[i])
    engine.process_network_ml({
        "source_ip": source_ips[i], "timestamp": base_time + i, "flow_id": flow_ids[i],
        "rf_threat_class": rf_labels_all[i], "rf_confidence": 1.0,
        "iforest_raw_score": if_scores_all[i],
    })

# -----------------------------------------------------------------
# 6. TIMED end-to-end loop — every branch, per flow, sequential (as coded)
# -----------------------------------------------------------------
e2e_latencies = []
for i in range(E2E_SAMPLE_SIZE):
    t0 = time.perf_counter()

    dns_result = classify_dns_query(domains[i], "A", pd.Timestamp.utcnow().isoformat(), source_ips[i])
    tls_result = classify_tls_session(ja3_fps[i], "tls", "client", pd.Timestamp.utcnow().isoformat(), source_ips[i])

    engine.process_network_ml({
        "source_ip": source_ips[i], "timestamp": base_time + i, "flow_id": flow_ids[i],
        "rf_threat_class": rf_labels_all[i], "rf_confidence": 1.0,
        "iforest_raw_score": if_scores_all[i],
    })
    engine.process_dns_branch({
        "source_ip": source_ips[i], "timestamp": base_time + i, "flow_id": flow_ids[i],
        "dns_flag": "DGA" if dns_result["flagged"] else None, "domain": domains[i],
    })
    engine.process_tls_branch({
        "source_ip": source_ips[i], "timestamp": base_time + i, "flow_id": flow_ids[i],
        "ja3_match": tls_result["flagged"], "ja3_hash": ja3_fps[i],
    })
    engine.process_behavioral_branch({
        "source_ip": source_ips[i], "timestamp": base_time + i, "flow_id": flow_ids[i],
        "byte_count": byte_counts[i], "flow_duration": flow_durations_sec[i],
        "pps": pps_values[i], "dest_ip": dest_ips[i],
    })

    e2e_latencies.append(time.perf_counter() - t0)

# -----------------------------------------------------------------
# 7. Report
# -----------------------------------------------------------------
arr = np.array(e2e_latencies)
print(f"END-TO-END: p50={np.percentile(arr,50)*1e3:.2f}ms  "
      f"p95={np.percentile(arr,95)*1e3:.2f}ms  "
      f"p99={np.percentile(arr,99)*1e3:.2f}ms  "
      f"throughput={len(arr)/arr.sum():.1f} flows/sec")
print(f"Alerts fired: {len(engine.alert_log)}   Near-misses: {len(engine.near_misses)}")