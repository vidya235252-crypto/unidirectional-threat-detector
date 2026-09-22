"""
train_isolation_forest.py

Trains a standalone Isolation Forest anomaly detector on the rebuilt
network-traffic dataset (cleaned_network_data_iforest.csv), establishes
a clean baseline of anomaly scores, and evaluates how well those scores
separate Normal Traffic from DDoS / Port Scanning / Bots.

Design choices (consistent with the project's locked architecture):
  - Fit ONLY on Normal Traffic rows from the TRAIN split. Isolation Forest
    is an unsupervised outlier detector; showing it attack rows at fit
    time would teach it "attack shape" rather than "normal shape", which
    defeats the point of using it as a corroborating signal alongside RF.
  - Attack Type is used for evaluation only, never passed to .fit().
  - Same 70/15/15 stratified split convention as the Random Forest run,
    so scores can later be joined back to RF's val/test predictions
    row-for-row (both come from the same split of the same file).
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
DATA_PATH = Path("data/processed/cleaned_network_data_iforest.csv")
MODEL_OUT = Path("models/isolation_forest_model.joblib")
DOCS_OUT = Path("docs/isolation_forest_results.md")
SCORES_OUT = Path("docs/isolation_forest_scores.csv")

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Fwd Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Min",
]
LABEL_COLUMN = "Attack Type"
NORMAL_LABEL = "Normal Traffic"

RANDOM_STATE = 42
CONTAMINATION = 0.05  # baseline guess; revisit once scores are inspected
N_ESTIMATORS = 200

# --------------------------------------------------------------------------
# 1. Load
# --------------------------------------------------------------------------
df = pd.read_csv(DATA_PATH)
missing_cols = set(FEATURE_COLUMNS + [LABEL_COLUMN]) - set(df.columns)
if missing_cols:
    raise ValueError(f"Dataset is missing expected columns: {missing_cols}")

X = df[FEATURE_COLUMNS]
y = df[LABEL_COLUMN]

# --------------------------------------------------------------------------
# 2. 70/15/15 stratified split (same convention as the RF run)
# --------------------------------------------------------------------------
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.30, stratify=y, random_state=RANDOM_STATE
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=RANDOM_STATE
)

print("Split sizes:")
print(f"  train: {len(X_train):,}  val: {len(X_val):,}  test: {len(X_test):,}")

# Sanity-check class prevalence held across the split (mirrors the RF check)
for name, y_split in [("train", y_train), ("val", y_val), ("test", y_test)]:
    prevalence = (y_split.value_counts(normalize=True) * 100).round(4)
    print(f"\n{name} class prevalence (%):\n{prevalence}")

# --------------------------------------------------------------------------
# 3. Fit ONLY on Normal Traffic rows from the TRAIN split
# --------------------------------------------------------------------------
X_train_normal = X_train[y_train == NORMAL_LABEL]
print(
    f"\nFitting Isolation Forest on {len(X_train_normal):,} Normal Traffic "
    f"train rows (out of {len(X_train):,} total train rows)."
)

iso_forest = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
iso_forest.fit(X_train_normal)

# --------------------------------------------------------------------------
# 4. Score generation on val + test
#    decision_function: higher = more normal, lower/negative = more anomalous
#    score_samples: raw path-length-based score (same ordering, unshifted)
#    predict: +1 = normal, -1 = anomaly, using the contamination threshold
# --------------------------------------------------------------------------
def score_split(X_split, y_split, split_name):
    decision_scores = iso_forest.decision_function(X_split)
    raw_scores = iso_forest.score_samples(X_split)
    predictions = iso_forest.predict(X_split)  # +1 normal, -1 anomaly

    out = pd.DataFrame(
        {
            "split": split_name,
            "Attack Type": y_split.values,
            "decision_function": decision_scores,
            "score_samples": raw_scores,
            "iforest_predicted_anomaly": predictions == -1,
        },
        index=X_split.index,
    )
    return out

val_scores = score_split(X_val, y_val, "val")
test_scores = score_split(X_test, y_test, "test")
all_scores = pd.concat([val_scores, test_scores], ignore_index=True)

SCORES_OUT.parent.mkdir(parents=True, exist_ok=True)
all_scores.to_csv(SCORES_OUT, index=False)
print(f"\nSaved per-row val+test scores to {SCORES_OUT}")

# --------------------------------------------------------------------------
# 5. Evaluation & alignment: mean/median anomaly score per Attack Type
# --------------------------------------------------------------------------
def summarize(scores_df, split_name):
    grouped = scores_df.groupby("Attack Type").agg(
        count=("decision_function", "size"),
        mean_decision_function=("decision_function", "mean"),
        median_decision_function=("decision_function", "median"),
        mean_score_samples=("score_samples", "mean"),
        median_score_samples=("score_samples", "median"),
        pct_flagged_anomaly=("iforest_predicted_anomaly", "mean"),
    )
    grouped["pct_flagged_anomaly"] = (grouped["pct_flagged_anomaly"] * 100).round(2)
    grouped = grouped.sort_values("mean_decision_function")
    print(f"\n=== {split_name} set: anomaly scores by Attack Type ===")
    print(grouped.round(4).to_string())
    return grouped

val_summary = summarize(val_scores, "Validation")
test_summary = summarize(test_scores, "Test")

# --------------------------------------------------------------------------
# 6. Write results to docs/
# --------------------------------------------------------------------------
DOCS_OUT.parent.mkdir(parents=True, exist_ok=True)
with open(DOCS_OUT, "w") as f:
    f.write("# Isolation Forest — Baseline Anomaly Score Results\n\n")
    f.write(
        f"Trained on {len(X_train_normal):,} Normal Traffic rows from the "
        f"train split of `{DATA_PATH}`.\n\n"
    )
    f.write(
        f"Params: `n_estimators={N_ESTIMATORS}`, "
        f"`contamination={CONTAMINATION}`, `random_state={RANDOM_STATE}`, "
        f"`n_jobs=-1`.\n\n"
    )
    f.write(
        "Lower `decision_function` / `score_samples` = more anomalous. "
        "`pct_flagged_anomaly` is the share of rows in that class the "
        "model's own contamination-derived threshold flagged as -1.\n\n"
    )
    f.write("## Validation set\n\n")
    f.write(val_summary.round(4).to_markdown())
    f.write("\n\n## Test set\n\n")
    f.write(test_summary.round(4).to_markdown())
    f.write("\n")

print(f"\nSaved summary report to {DOCS_OUT}")

# --------------------------------------------------------------------------
# 7. Save model
# --------------------------------------------------------------------------
MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(iso_forest, MODEL_OUT)
print(f"\nSaved trained Isolation Forest to {MODEL_OUT}")

# Quick separation check printed to console: is Bots meaningfully more
# anomalous than Normal Traffic on the test set?
bots_mean = test_summary.loc["Bots", "mean_decision_function"] if "Bots" in test_summary.index else None
normal_mean = test_summary.loc[NORMAL_LABEL, "mean_decision_function"]
if bots_mean is not None:
    print(
        f"\nBots mean decision_function ({bots_mean:.4f}) vs. "
        f"Normal Traffic mean decision_function ({normal_mean:.4f}): "
        f"{'Bots score lower (more anomalous), as expected' if bots_mean < normal_mean else 'WARNING: Bots not scoring more anomalous than Normal Traffic — investigate'}"
    )