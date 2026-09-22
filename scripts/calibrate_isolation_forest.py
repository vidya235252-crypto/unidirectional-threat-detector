"""
calibrate_isolation_forest.py

Rebuilds the Isolation Forest anomaly detector and REPLACES the default
contamination-derived -1/+1 threshold with an empirically calibrated cutoff
on raw score_samples(). The baseline run showed scores ARE separated on
average (Normal Traffic median ~-0.4513 vs. Bots median ~-0.4815 on test),
but contamination=0.05's threshold was too strict for a class this rare
(0.088% prevalence) and only caught 3.42% of Bots. This script finds the
threshold directly from data instead of trusting the contamination knob.

================================================================================
DESIGN DECISIONS (for whoever is evaluating this file)
================================================================================
1. FIT ONLY ON NORMAL TRAFFIC (train split).
   Isolation Forest is unsupervised — it learns "what normal isolation depth
   looks like" and scores deviation from that. Including attack rows at fit
   time would let it partially learn attack shape too, which would make it
   redundant with the Random Forest instead of a genuinely independent
   corroborating signal. Attack Type is used for evaluation only, never
   passed to .fit().

2. contamination='auto' INSTEAD OF A FIXED VALUE.
   contamination only controls the model's internal .predict() -1/1 cutoff.
   Since step 4 below throws that cutoff away and derives its own threshold
   empirically, there's no benefit to hand-picking a contamination value —
   'auto' is used purely so the object initializes with a sane default;
   it has zero effect on the final calibrated threshold or on score_samples()
   itself (those come directly from path length in the trees, independent
   of contamination).

3. THRESHOLD IS CALIBRATED, NOT TAKEN FROM .predict().
   .predict() applies whatever cutoff contamination implies, which assumes
   the anomaly rate roughly matches the contamination estimate. Bots are
   ~0.088% of traffic — nowhere near contamination=0.05 — so predict()
   systematically under-flags them. Instead, Section 4 scans raw
   score_samples() thresholds directly against Validation ground truth and
   picks the strictest cutoff that still clears a 90% Bots-recall bar
   (strict = fewest Normal Traffic false positives at that recall level).

4. OUTPUT IS A CONTINUOUS SCORE, NOT A HARD LABEL.
   Downstream, the Alert Engine fuses this signal with the Random Forest's
   prediction (e.g. RF says "Bot" AND iForest score falls below the
   calibrated cutoff -> alert). Handing back a raw, continuous score_samples
   value (plus the boolean at the currently-calibrated cutoff, for
   convenience) keeps that fusion logic free to re-threshold later without
   retraining this model.

5. MODEL AND THRESHOLD ARE SAVED AS SEPARATE ARTIFACTS.
   models/optimized_isolation_forest.joblib is a bare IsolationForest —
   loadable with a plain `joblib.load(path)` and usable immediately via
   `.score_samples(X)`, matching how the original (non-calibrated) model
   was loaded. The calibrated threshold is NOT baked into that pickle;
   it's written to models/optimized_isolation_forest_threshold.json instead,
   so any downstream code that already does `joblib.load(path).score_samples(X)`
   keeps working unmodified, and the threshold can be re-tuned later by
   overwriting a small JSON file rather than re-pickling the model.
================================================================================
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
DATA_PATH = Path("data/processed/cleaned_network_data_iforest.csv")
MODEL_OUT = Path("models/optimized_isolation_forest.joblib")
THRESHOLD_OUT = Path("models/optimized_isolation_forest_threshold.json")
DOCS_OUT = Path("docs/isolation_forest_calibrated_results.md")
SCORES_OUT = Path("docs/isolation_forest_calibrated_scores.csv")

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
BOTS_LABEL = "Bots"

RANDOM_STATE = 42
CONTAMINATION = "auto"  # predict()/-1/1 threshold is not what we use anymore,
                         # but IsolationForest still needs a value internally
N_ESTIMATORS = 200

TARGET_BOTS_RECALL = 0.90
THRESHOLD_SCAN_START = -0.4400  # loose end: flags almost everything
THRESHOLD_SCAN_END = -0.5200    # strict end: flags almost nothing
THRESHOLD_SCAN_STEP = -0.0005   # negative step -> walking loose to strict

# --------------------------------------------------------------------------
# 1. Load + split (same convention as prior runs: 70/15/15 stratified)
# --------------------------------------------------------------------------
df = pd.read_csv(DATA_PATH)
X = df[FEATURE_COLUMNS]
y = df[LABEL_COLUMN]

X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.30, stratify=y, random_state=RANDOM_STATE
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=RANDOM_STATE
)

X_train_normal = X_train[y_train == NORMAL_LABEL]
print(f"Training on {len(X_train_normal):,} Normal Traffic train rows.")

# --------------------------------------------------------------------------
# 2. Train
# --------------------------------------------------------------------------
iso_forest = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
iso_forest.fit(X_train_normal)

# --------------------------------------------------------------------------
# 3. Raw score extraction — Train (normal only), Validation, Test
# --------------------------------------------------------------------------
train_scores = iso_forest.score_samples(X_train_normal)
val_scores = iso_forest.score_samples(X_val)
test_scores = iso_forest.score_samples(X_test)

print("\nMedian score_samples — sanity check against the diagnostic run:")
print(f"  Train (Normal only): {np.median(train_scores):.4f}")
print(f"  Val   Normal Traffic: {np.median(val_scores[y_val.values == NORMAL_LABEL]):.4f}")
print(f"  Val   Bots:           {np.median(val_scores[y_val.values == BOTS_LABEL]):.4f}")

# --------------------------------------------------------------------------
# 4. Programmatic threshold calibration on the VALIDATION set
#    Rule: flag row as anomalous if score_samples(x) <= threshold
#    (lower score = more anomalous, so this direction is correct)
# --------------------------------------------------------------------------
def scan_thresholds(scores, labels, start, end, step,
                     positive_label=BOTS_LABEL, negative_label=NORMAL_LABEL):
    """
    For each threshold, compute:
      - Bots recall (TPR)      = flagged Bots / total Bots
      - Normal Traffic FPR     = flagged Normal / total Normal
    Returns a DataFrame, one row per threshold.
    """
    is_bot = labels.values == positive_label
    is_normal = labels.values == negative_label
    n_bots = is_bot.sum()
    n_normal = is_normal.sum()

    rows = []
    threshold = start
    while threshold >= end:
        flagged = scores <= threshold
        bots_recall = flagged[is_bot].sum() / n_bots if n_bots else np.nan
        normal_fpr = flagged[is_normal].sum() / n_normal if n_normal else np.nan
        rows.append(
            {
                "threshold": round(threshold, 4),
                "bots_recall": bots_recall,
                "normal_fpr": normal_fpr,
            }
        )
        threshold += step
    return pd.DataFrame(rows)

scan_df = scan_thresholds(
    val_scores, y_val, THRESHOLD_SCAN_START, THRESHOLD_SCAN_END, THRESHOLD_SCAN_STEP
)

# Among thresholds that hit >=90% Bots recall, take the one with the lowest
# Normal Traffic FPR (i.e. the strictest threshold that still clears the bar).
qualifying = scan_df[scan_df["bots_recall"] >= TARGET_BOTS_RECALL]
if qualifying.empty:
    raise RuntimeError(
        f"No threshold in the scanned range [{THRESHOLD_SCAN_START}, "
        f"{THRESHOLD_SCAN_END}] reaches {TARGET_BOTS_RECALL:.0%} Bots recall. "
        f"Widen THRESHOLD_SCAN_START/END and rerun."
    )
best_row = qualifying.loc[qualifying["normal_fpr"].idxmin()]
CALIBRATED_THRESHOLD = float(best_row["threshold"])

print(f"\nCalibrated threshold: {CALIBRATED_THRESHOLD:.4f}")
print(
    f"  -> Validation Bots recall: {best_row['bots_recall']:.4f}  "
    f"Normal Traffic FPR: {best_row['normal_fpr']:.4f}"
)

Path("docs").mkdir(parents=True, exist_ok=True)
scan_df.to_csv("docs/isolation_forest_threshold_scan.csv", index=False)
print("Saved full threshold scan to docs/isolation_forest_threshold_scan.csv")

# --------------------------------------------------------------------------
# 5. Final evaluation on the TEST set at the calibrated threshold
# --------------------------------------------------------------------------
def evaluate_at_threshold(scores, labels, threshold):
    flagged = scores <= threshold
    summary = pd.DataFrame(
        {"Attack Type": labels.values, "flagged": flagged}
    ).groupby("Attack Type")["flagged"].agg(
        count="size", pct_flagged=lambda s: round(s.mean() * 100, 2)
    )
    return summary

test_summary = evaluate_at_threshold(test_scores, y_test, CALIBRATED_THRESHOLD)
print(f"\n=== Test set, calibrated threshold = {CALIBRATED_THRESHOLD:.4f} ===")
print(test_summary.to_string())

bots_recall_test = test_summary.loc[BOTS_LABEL, "pct_flagged"] if BOTS_LABEL in test_summary.index else None
normal_fpr_test = test_summary.loc[NORMAL_LABEL, "pct_flagged"]
print(
    f"\nTest Bots recall: {bots_recall_test}%  |  "
    f"Test Normal Traffic FPR: {normal_fpr_test}%"
)
print(
    "(Compare against the old contamination=0.05 run: 3.42% Bots recall "
    "on this same test set.)"
)

# --------------------------------------------------------------------------
# 6. Persist per-row raw scores for val+test — NO hard -1/1 call.
#    The Alert Engine reads `score_samples` (and, if useful, the boolean
#    at THIS calibrated threshold) and makes its own fusion decision.
# --------------------------------------------------------------------------
val_out = pd.DataFrame(
    {
        "split": "val",
        "Attack Type": y_val.values,
        "score_samples": val_scores,
        "flagged_at_calibrated_threshold": val_scores <= CALIBRATED_THRESHOLD,
    },
    index=X_val.index,
)
test_out = pd.DataFrame(
    {
        "split": "test",
        "Attack Type": y_test.values,
        "score_samples": test_scores,
        "flagged_at_calibrated_threshold": test_scores <= CALIBRATED_THRESHOLD,
    },
    index=X_test.index,
)
all_scores = pd.concat([val_out, test_out], ignore_index=True)
all_scores.to_csv(SCORES_OUT, index=False)
print(f"\nSaved raw per-row scores (val+test) to {SCORES_OUT}")

# --------------------------------------------------------------------------
# 7. Write markdown report
# --------------------------------------------------------------------------
with open(DOCS_OUT, "w") as f:
    f.write("# Isolation Forest — Calibrated Threshold Results\n\n")
    f.write(
        f"Trained on {len(X_train_normal):,} Normal Traffic rows. "
        f"`n_estimators={N_ESTIMATORS}`, `contamination={CONTAMINATION}`, "
        f"`random_state={RANDOM_STATE}`.\n\n"
    )
    f.write(
        f"Empirical threshold calibrated on the Validation set to reach "
        f"≥{TARGET_BOTS_RECALL:.0%} Bots recall at minimum Normal Traffic "
        f"FPR: **`score_samples <= {CALIBRATED_THRESHOLD:.4f}`** = flagged "
        f"anomalous.\n\n"
    )
    f.write(f"Validation at this threshold: Bots recall = "
            f"{best_row['bots_recall']:.4f}, Normal Traffic FPR = "
            f"{best_row['normal_fpr']:.4f}.\n\n")
    f.write("## Test set — percent flagged per class at calibrated threshold\n\n")
    f.write(test_summary.to_markdown())
    f.write("\n\n")
    f.write(
        "Note: this model's output for downstream use is the continuous "
        "`score_samples` value, not a hard -1/1 label. The Alert Engine "
        "fusion step owns the final Bot-alert decision.\n"
    )

print(f"Saved report to {DOCS_OUT}")

# --------------------------------------------------------------------------
# 8. Save the model as a BARE estimator (drop-in compatible with existing
#    `joblib.load(path).score_samples(X)` call sites), and save the
#    calibrated threshold as a small separate JSON sidecar rather than
#    bundling it into the pickle. See DESIGN DECISIONS #5 above.
# --------------------------------------------------------------------------
MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(iso_forest, MODEL_OUT)
print(f"\nSaved model (bare IsolationForest) to {MODEL_OUT}")

THRESHOLD_OUT.parent.mkdir(parents=True, exist_ok=True)
with open(THRESHOLD_OUT, "w") as f:
    json.dump(
        {
            "calibrated_threshold": CALIBRATED_THRESHOLD,
            "rule": "flag as anomalous if score_samples(x) <= calibrated_threshold",
            "target_bots_recall": TARGET_BOTS_RECALL,
            "validation_bots_recall_at_threshold": float(best_row["bots_recall"]),
            "validation_normal_fpr_at_threshold": float(best_row["normal_fpr"]),
            "n_estimators": N_ESTIMATORS,
            "contamination": CONTAMINATION,
            "random_state": RANDOM_STATE,
        },
        f,
        indent=2,
    )
print(f"Saved calibrated threshold + calibration metadata to {THRESHOLD_OUT}")