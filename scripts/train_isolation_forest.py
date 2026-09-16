"""
train_isolation_forest.py
PS26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Trains an Isolation Forest (IF) on BENIGN-only traffic to produce a
per-flow `anomaly_score` — a corroborating "how normal does this look"
signal alongside the Random Forest's `threat_class` output.

Hard rules this script enforces (locked in session handoff v2):
  1. IF is fit ONLY on BENIGN rows from the TRAIN split. TEST rows and
     every attack row are never seen during fitting.
  2. The anomaly-decision threshold is calibrated on a held-out slice
     of BENIGN TRAIN data — never on TEST data, never on attack rows.
  3. The log1p transform is NOT applied inside this script. It is
     already baked into the input file used here,
     `cicids2017_12_features_cleaned_withlog.csv` (produced earlier by
     clean_dataset.py's `apply_log1p_transform()` / `LOG1P_COLUMNS`).
     This script only reads it — applying it again here would
     log-transform the data a second time and silently corrupt it.
  4. No class_weight / balancing — IF must learn the true, undisturbed
     shape of normal traffic.
  5. IAT_CV (the RF-only engineered feature) is intentionally excluded.
  6. Same reproducible split as the heuristic and RF: test_size=0.20,
     stratify=Label, random_state=42.

ASSUMPTION FLAGGED FOR REVIEW: this script assumes
cicids2017_12_features_cleaned_withlog.csv has the exact same rows,
row order, and Label column as cicids2017_12_features_cleaned.csv —
only the LOG1P_COLUMNS values differ (log1p is a deterministic,
elementwise transform, so applying it before vs. after the train/test
split makes no difference and introduces no leakage). If this file
was built any other way, flag it before running.

Usage (no path arguments needed for a standard checkout):
    python train_isolation_forest.py

Usage (overriding any path):
    python train_isolation_forest.py --data path/to/other_file.csv
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# Only the column list is needed here — for logging which columns are
# already log1p-transformed in the input file. The transform itself is
# NOT re-applied (see module docstring, point 3).
from clean_dataset import LOG1P_COLUMNS

MODEL_VERSION = "if_v1"
LABEL_COL = "Label"
BENIGN_LABEL = "BENIGN"
RANDOM_STATE = 42

# 11 raw CICIDS2017 features — same set RF used before adding IAT_CV.
# IAT_CV is deliberately excluded: it was purpose-built for supervised
# Bot-vs-BENIGN classification, not for learning the shape of normal.
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Count",
    "Average Packet Size",
    "Down/Up Ratio",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data", type=Path,
        default=Path("data/processed/cicids2017_12_features_cleaned_withlog.csv"),
        help=(
            "Path to the already-cleaned, already-log1p-transformed "
            "dataset used for IF training/eval. Defaults to the "
            "standard project location so no manual path is needed "
            "on a normal checkout."
        ),
    )
    parser.add_argument(
        "--metrics-out", type=Path,
        default=Path("docs/isolation_forest_metrics.md"),
        help="Where to write the human-readable metrics report",
    )
    parser.add_argument(
        "--scores-out", type=Path,
        default=Path("data/processed/isolation_forest_test_scores.csv"),
        help="Where to write per-row TEST-set anomaly scores for review",
    )
    parser.add_argument(
        "--model-out", type=Path,
        default=Path("models/isolation_forest_v1.joblib"),
        help="Where to save the fitted model",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=200,
        help="Number of isolation trees (default: 200)",
    )
    parser.add_argument(
        "--contamination", type=float, default=0.01,
        help=(
            "Expected fraction of anomalies in the FIT set. Kept low "
            "(default 0.01) since the fit set is deliberately BENIGN-"
            "only, not sklearn's 0.1 default — see interview Q2 from "
            "the walkthrough session."
        ),
    )
    parser.add_argument(
        "--calibration-frac", type=float, default=0.2,
        help="Fraction of BENIGN train rows held out to set the threshold",
    )
    parser.add_argument(
        "--threshold-percentile", type=float, default=99.0,
        help="Percentile of calibration anomaly scores used as the cutoff",
    )
    return parser.parse_args()


def load_dataset(path: Path) -> pd.DataFrame:
    """Load the cleaned dataset and log basic shape/label info."""
    df = pd.read_csv(path)
    print(f"[load] {path} -> {len(df):,} rows, {df.shape[1]} columns")
    label_counts = df[LABEL_COL].value_counts(normalize=True) * 100
    for label, pct in label_counts.items():
        print(f"[load]   {label:<10} {pct:6.2f}%  ({(df[LABEL_COL]==label).sum():,} rows)")
    return df


def create_train_test_split(df: pd.DataFrame):
    """Same reproducible split used by the heuristic baseline and RF."""
    train_df, test_df = train_test_split(
        df, test_size=0.20, stratify=df[LABEL_COL], random_state=RANDOM_STATE,
    )
    print(f"[split] train={len(train_df):,} rows | test={len(test_df):,} rows")
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)


def extract_benign_training_set(train_df: pd.DataFrame) -> pd.DataFrame:
    """Isolate BENIGN-only rows from the TRAIN split. Attack rows and
    TEST rows must never reach the fit step."""
    benign_df = train_df[train_df[LABEL_COL] == BENIGN_LABEL].reset_index(drop=True)
    pct = 100 * len(benign_df) / len(train_df)
    print(f"[benign] {len(benign_df):,} / {len(train_df):,} train rows are BENIGN ({pct:.2f}%)")
    return benign_df


def split_fit_and_calibration(benign_df: pd.DataFrame, calibration_frac: float):
    """Hold out a slice of BENIGN train data purely to calibrate the
    anomaly threshold later — this slice is never used for .fit()."""
    fit_df, calib_df = train_test_split(
        benign_df, test_size=calibration_frac, random_state=RANDOM_STATE,
    )
    print(f"[calib-split] fit={len(fit_df):,} rows | calibration={len(calib_df):,} rows")
    return fit_df.reset_index(drop=True), calib_df.reset_index(drop=True)


def confirm_log1p_present(df: pd.DataFrame) -> None:
    """Sanity-check only — the input file is expected to already carry
    the log1p transform on LOG1P_COLUMNS. We don't re-apply it; we just
    confirm those columns exist so a wrong file fails loudly and early."""
    missing = [c for c in LOG1P_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Expected log1p-transformed columns missing from input "
            f"file: {missing}. Wrong file passed to --data?"
        )
    print(f"[log1p] confirmed already applied upstream to: {LOG1P_COLUMNS}")


def train_isolation_forest(X_fit: pd.DataFrame, n_estimators: int, contamination: float) -> IsolationForest:
    """Fit IF on BENIGN-only, log1p-transformed features. No class_weight
    or balancing — the model must learn the true shape of normal."""
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_fit)
    print(f"[fit] IsolationForest trained on {len(X_fit):,} BENIGN rows "
          f"(n_estimators={n_estimators}, contamination={contamination})")
    return model


def compute_anomaly_scores(model: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    """Higher score = more anomalous.
    sklearn's score_samples() is higher-for-normal, so we invert it to
    match the project convention (anomaly_score: higher = more anomalous)."""
    return -model.score_samples(X)


def calibrate_threshold(calib_scores: np.ndarray, percentile: float) -> float:
    """Set the anomalous/normal cutoff using ONLY held-out BENIGN data.
    Never calibrated on TEST rows or attack rows — see session handoff
    Section 4 and the threshold-calibration discussion."""
    threshold = np.percentile(calib_scores, percentile)
    print(f"[threshold] {percentile:.1f}th percentile of BENIGN calibration "
          f"scores = {threshold:.5f}")
    return threshold


def evaluate_on_test(model: IsolationForest, test_df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """Score every TEST row (all classes) and flag it anomalous or not.
    Labels are used here ONLY for reporting — never for tuning."""
    X_test = test_df[FEATURE_COLUMNS]
    scores = compute_anomaly_scores(model, X_test)
    flagged = scores > threshold

    results = test_df[[LABEL_COL]].copy()
    results["anomaly_score"] = scores
    results["flagged_anomalous"] = flagged
    print(f"[eval] scored {len(results):,} TEST rows against threshold={threshold:.5f}")
    return results


def summarise_per_class(results: pd.DataFrame) -> pd.DataFrame:
    """Per-class: mean/median anomaly_score and % flagged anomalous.
    For non-BENIGN classes, '% flagged' reads as IF's corroboration
    (recall-like) rate. For BENIGN, it IS the false-positive rate."""
    summary = results.groupby(LABEL_COL).agg(
        support=("anomaly_score", "size"),
        mean_score=("anomaly_score", "mean"),
        median_score=("anomaly_score", "median"),
        pct_flagged=("flagged_anomalous", lambda s: 100 * s.mean()),
    ).round(5)
    print("[summary]\n" + summary.to_string())
    return summary


def write_metrics_report(
    path: Path,
    n_fit: int,
    n_calib: int,
    n_estimators: int,
    contamination: float,
    threshold_percentile: float,
    threshold: float,
    summary: pd.DataFrame,
) -> None:
    """Write a versioned, human-readable report — mirrors the format
    and diffability of random_forest_metrics.md / v2."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Isolation Forest — PS26145",
        "",
        "## Training setup",
        f"- Model version: `{MODEL_VERSION}`",
        f"- Fit rows (BENIGN, TRAIN split only): {n_fit:,}",
        f"- Calibration rows (held-out BENIGN, TRAIN split): {n_calib:,}",
        f"- n_estimators: {n_estimators}",
        f"- contamination: {contamination}",
        f"- Features ({len(FEATURE_COLUMNS)}): {', '.join(FEATURE_COLUMNS)}",
        f"- log1p columns (pre-applied upstream in the input file): "
        f"{', '.join(LOG1P_COLUMNS)}",
        "",
        "## Threshold calibration",
        f"- Percentile used: {threshold_percentile}",
        f"- Resulting threshold on anomaly_score: {threshold:.5f}",
        "- Calibrated on held-out BENIGN TRAIN rows only "
        "(never TEST, never attack rows)",
        "",
        "## TEST-set results (labels used for reporting only, not tuning)",
        "",
        "| Label | Support | Mean anomaly_score | Median anomaly_score | % flagged anomalous |",
        "|---|---|---|---|---|",
    ]
    for label, row in summary.iterrows():
        lines.append(
            f"| {label} | {int(row['support']):,} | {row['mean_score']:.5f} "
            f"| {row['median_score']:.5f} | {row['pct_flagged']:.2f}% |"
        )
    lines += [
        "",
        "> Note: BENIGN's '% flagged anomalous' is IF's false-positive rate.",
        "> Non-BENIGN rows' '% flagged anomalous' is how often IF's "
        "independent signal agrees a flow looks abnormal — NOT a "
        "classification recall, since IF never saw class labels.",
        "> anomaly_score is a corroborating signal only — it must never "
        "be presented downstream as a named classified threat.",
    ]
    path.write_text("\n".join(lines))
    print(f"[report] written to {path}")


def main() -> None:
    args = parse_args()

    df = load_dataset(args.data)
    confirm_log1p_present(df)
    train_df, test_df = create_train_test_split(df)

    benign_train = extract_benign_training_set(train_df)
    fit_df, calib_df = split_fit_and_calibration(benign_train, args.calibration_frac)

    model = train_isolation_forest(
        fit_df[FEATURE_COLUMNS], args.n_estimators, args.contamination,
    )

    calib_scores = compute_anomaly_scores(model, calib_df[FEATURE_COLUMNS])
    threshold = calibrate_threshold(calib_scores, args.threshold_percentile)

    results = evaluate_on_test(model, test_df, threshold)
    summary = summarise_per_class(results)

    write_metrics_report(
        args.metrics_out, len(fit_df), len(calib_df),
        args.n_estimators, args.contamination,
        args.threshold_percentile, threshold, summary,
    )

    args.scores_out.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(args.scores_out, index=False)
    print(f"[scores] per-row TEST scores written to {args.scores_out}")

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_out)
    print(f"[model] saved to {args.model_out}")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)