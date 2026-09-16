"""
heuristic_baseline.py

PS26145 — unidirectional-threat-detector

Single-file heuristic (rule-based) baseline: train/test split, threshold
derivation with printed insights, rule evaluation, and metrics reporting —
consolidated into one place (the earlier split-file / stats-file split was
unnecessary ceremony for what is, correctly, just sklearn + if/else).

Pipeline, end to end
--------------------
1. Load the cleaned dataset (raw values — no log1p; that's deferred to
   Isolation Forest training only, see clean_dataset.py).
2. Stratified 80/20 train/test split, fixed random_state=42. REUSE THIS
   EXACT SEED in the Random Forest / Isolation Forest training scripts
   later, or "RF beat the baseline" stops being apples-to-apples.
3. Derive rule thresholds from the TRAIN split's BENIGN rows only (never
   test, never non-BENIGN — this is deliberately a "known-clean" baseline):
     - P95 of Flow Packets/s        -> DDoS rule
     - P5  of Flow Duration         -> PortScan rule
     - P25 of Average Packet Size   -> PortScan + Bot rules
     - High_Threshold (Flow Duration) -> Bot rule. Auto-selected from
       {P75, P90, P95} of BENIGN Flow Duration using Youden's J
       (TPR on Bot minus FPR on BENIGN, both measured on TRAIN), so the
       choice is evidence-based rather than picked by eye.
4. Apply the three rules as a priority cascade — DDoS, then PortScan,
   then Bot, default BENIGN — with all four tightenings applied:
     a. SYN Flag Count >= 1        (was =="1"; catches multi-SYN retransmits)
     b. PortScan adds Total Backward Packets == 0 (a scanned closed/
        filtered port gets NO response — stronger signal than packet
        count alone)
     c. Bot rule's IAT ratio (Flow IAT Std / Flow IAT Mean) is computed
        with NaN where Flow IAT Mean == 0, and NaN < threshold evaluates
        to False in pandas/numpy — so rows with an undefined ratio are
        automatically excluded from the Bot rule rather than crashing
        or being silently treated as "0 = perfectly periodic"
     d. Bot rule adds Total Fwd Packets >= 3 (true periodicity needs more
        than a single packet; guards against idle long BENIGN connections
        false-positiving as C2 beaconing)
5. Score on the TEST split (never touched during threshold derivation):
   confusion matrix, per-class precision/recall/F1, overall accuracy,
   and BENIGN false-positive rate as the headline safety number (plain
   accuracy is misleading on an ~90% BENIGN dataset).
6. Print thresholds, split ratio, and metrics clearly; also write them
   to a Markdown file for evaluator documentation and as the floor
   number to beat once Random Forest exists.

Usage
-----
    python heuristic_baseline.py \\
        --input data/processed/cicids2017_12_features_cleaned.csv \\
        --summary-output docs/heuristic_baseline_metrics.md
"""

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

LABEL_COL = "Label"
TEST_SIZE = 0.20
RANDOM_STATE = 42  # Reuse this exact value in RF/IF training scripts.
CANDIDATE_PERCENTILES = [75, 90, 95]
TIER1_LABELS = ["BENIGN", "Bot", "PortScan", "DDoS"]

# Every raw feature the rules and the insight printout reference.
STAT_COLUMNS = [
    "Flow Packets/s",
    "Flow Duration",
    "Average Packet Size",
    "Total Fwd Packets",
    "Total Backward Packets",
    "SYN Flag Count",
    "Down/Up Ratio",
    "Flow IAT Mean",
    "Flow IAT Std",
]


# --------------------------------------------------------------------------
# 1. Load
# --------------------------------------------------------------------------

def load_data(input_path: str) -> pd.DataFrame:
    log.info("Loading cleaned dataset from %s", input_path)
    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()
    log.info("Loaded %s rows, %s columns", f"{len(df):,}", df.shape[1])
    return df


# --------------------------------------------------------------------------
# 2. Split
# --------------------------------------------------------------------------

def split_stratified(df: pd.DataFrame) -> tuple:
    print("\n" + "=" * 78)
    print(f"TRAIN/TEST SPLIT — {int((1 - TEST_SIZE) * 100)}% train / {int(TEST_SIZE * 100)}% test, "
          f"stratified by Label, random_state={RANDOM_STATE}")
    print("=" * 78)

    train_df, test_df = train_test_split(
        df, test_size=TEST_SIZE, stratify=df[LABEL_COL], random_state=RANDOM_STATE,
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    print(f"{'Label':<12} {'Train count':>14} {'Train %':>10}   {'Test count':>14} {'Test %':>10}")
    for label in TIER1_LABELS:
        tr = (train_df[LABEL_COL] == label).sum()
        te = (test_df[LABEL_COL] == label).sum()
        tr_pct = tr / len(train_df) * 100
        te_pct = te / len(test_df) * 100
        print(f"{label:<12} {tr:>14,} {tr_pct:>9.4f}%   {te:>14,} {te_pct:>9.4f}%")

    return train_df, test_df


# --------------------------------------------------------------------------
# 3. Threshold derivation (TRAIN split, BENIGN rows only)
# --------------------------------------------------------------------------

def add_iat_ratio(df: pd.DataFrame) -> pd.DataFrame:
    """Flow IAT Std / Flow IAT Mean, NaN where Mean == 0 (guard c)."""
    df = df.copy()
    mean = df["Flow IAT Mean"]
    std = df["Flow IAT Std"]
    df["Flow IAT Std/Mean Ratio"] = np.where(mean == 0, np.nan, std / mean)
    return df


def print_feature_insights(df: pd.DataFrame) -> None:
    """Min/Max/P75/P90/P95 per label, for every rule-relevant feature."""
    print("\n" + "=" * 78)
    print("FEATURE INSIGHTS (TRAIN split, per label) — min / P75 / P90 / P95 / max")
    print("=" * 78)

    for column in STAT_COLUMNS + ["Flow IAT Std/Mean Ratio"]:
        print(f"\n--- {column} ---")
        print(f"{'Label':<12} {'Count':>10} {'Min':>14} {'P75':>14} {'P90':>14} {'P95':>14} {'Max':>14}")
        for label in TIER1_LABELS:
            series = df.loc[df[LABEL_COL] == label, column].dropna()
            if series.empty:
                continue
            print(
                f"{label:<12} {len(series):>10,} "
                f"{series.min():>14,.4f} {np.percentile(series, 75):>14,.4f} "
                f"{np.percentile(series, 90):>14,.4f} {np.percentile(series, 95):>14,.4f} "
                f"{series.max():>14,.4f}"
            )


def select_high_threshold(train_df: pd.DataFrame) -> float:
    """Auto-select the Bot rule's Flow Duration cutoff via Youden's J
    (TPR on Bot - FPR on BENIGN), evaluated on TRAIN only across
    {P75, P90, P95} candidates. Prints the full comparison so the pick
    is auditable, not a black box.
    """
    print("\n" + "=" * 78)
    print("HIGH_THRESHOLD SELECTION (Bot rule, Flow Duration) — Youden's J on TRAIN")
    print("=" * 78)

    benign = train_df.loc[train_df[LABEL_COL] == "BENIGN", "Flow Duration"]
    bot = train_df.loc[train_df[LABEL_COL] == "Bot", "Flow Duration"]

    print(f"{'Percentile':<12} {'Threshold':>16} {'FPR (BENIGN)':>15} {'TPR (Bot)':>12} {'J = TPR-FPR':>14}")
    best_p, best_threshold, best_j = None, None, -np.inf
    for p in CANDIDATE_PERCENTILES:
        threshold = np.percentile(benign, p)
        fpr = (benign > threshold).mean()
        tpr = (bot > threshold).mean() if len(bot) else 0.0
        j = tpr - fpr
        marker = ""
        if j > best_j:
            best_j, best_p, best_threshold = j, p, threshold
        print(f"P{p:<11} {threshold:>16,.4f} {fpr * 100:>14.4f}% {tpr * 100:>11.4f}% {j:>14.4f}")

    print(f"\nSelected: P{best_p} (threshold = {best_threshold:,.4f}), J = {best_j:.4f}")
    print("Reasoning: highest (TPR_Bot - FPR_BENIGN) among the three candidates — "
          "the percentile that best separates Bot's long-lived flows from BENIGN's, "
          "on train data only, so it carries no test-set information.")

    if best_j <= 0:
        log.warning("Best J-score is <= 0 — Flow Duration alone does NOT separate Bot from "
                     "BENIGN in this data. The Bot rule will lean entirely on the IAT-ratio "
                     "and packet-count conditions; expect low Bot recall from this heuristic.")

    return best_threshold


def derive_thresholds(train_df: pd.DataFrame) -> dict:
    print("\n" + "=" * 78)
    print("THRESHOLD DERIVATION (TRAIN split, BENIGN rows only)")
    print("=" * 78)

    benign = train_df[train_df[LABEL_COL] == "BENIGN"]

    p95_packets = np.percentile(benign["Flow Packets/s"], 95)
    p5_duration = np.percentile(benign["Flow Duration"], 5)
    p25_packet_size = np.percentile(benign["Average Packet Size"], 25)
    high_threshold = select_high_threshold(train_df)

    thresholds = {
        "P95_Packets_Per_Sec": p95_packets,
        "P5_Duration": p5_duration,
        "P25_Packet_Size": p25_packet_size,
        "High_Threshold_Duration": high_threshold,
    }

    print("\nFinal thresholds:")
    for name, value in thresholds.items():
        print(f"  {name:<26} = {value:,.4f}")

    return thresholds


# --------------------------------------------------------------------------
# 4. Rule application (priority cascade, vectorized)
# --------------------------------------------------------------------------

def apply_rules(df: pd.DataFrame, thresholds: dict) -> pd.Series:
    df = add_iat_ratio(df)

    # (a) SYN Flag Count >= 1, not == 1 — catches multi-SYN retransmits.
    ddos_mask = (
        (df["SYN Flag Count"] >= 1)
        & (df["Flow Packets/s"] > thresholds["P95_Packets_Per_Sec"])
        & (df["Down/Up Ratio"] < 0.1)
    )

    # (b) Total Backward Packets == 0 — a scanned closed/filtered port
    # gets no response; stronger than forward-packet count alone.
    portscan_mask = (
        (df["Flow Duration"] < thresholds["P5_Duration"])
        & (df["Total Fwd Packets"] <= 2)
        & (df["Average Packet Size"] < thresholds["P25_Packet_Size"])
        & (df["Total Backward Packets"] == 0)
    )

    # (c) NaN ratio (Flow IAT Mean == 0) evaluates to False here —
    # those rows are automatically excluded, no explicit guard needed.
    # (d) Total Fwd Packets >= 3 — periodicity needs more than one packet.
    bot_mask = (
        (df["Flow IAT Std/Mean Ratio"] < 0.1)
        & (df["Average Packet Size"] < thresholds["P25_Packet_Size"])
        & (df["Flow Duration"] > thresholds["High_Threshold_Duration"])
        & (df["Total Fwd Packets"] >= 3)
    )

    predictions = np.select(
        [ddos_mask, portscan_mask, bot_mask],
        ["DDoS", "PortScan", "Bot"],
        default="BENIGN",
    )
    return pd.Series(predictions, index=df.index, name="Predicted_Label")


# --------------------------------------------------------------------------
# 5. Evaluation
# --------------------------------------------------------------------------

def evaluate(test_df: pd.DataFrame, y_pred: pd.Series) -> dict:
    y_true = test_df[LABEL_COL]

    print("\n" + "=" * 78)
    print("EVALUATION (TEST split — never used to derive thresholds)")
    print("=" * 78)

    cm = confusion_matrix(y_true, y_pred, labels=TIER1_LABELS)
    print("\nConfusion matrix (rows = actual, columns = predicted):")
    header = f"{'':<12}" + "".join(f"{l:>12}" for l in TIER1_LABELS)
    print(header)
    for i, label in enumerate(TIER1_LABELS):
        row = f"{label:<12}" + "".join(f"{cm[i][j]:>12,}" for j in range(len(TIER1_LABELS)))
        print(row)

    report = classification_report(y_true, y_pred, labels=TIER1_LABELS, output_dict=True, zero_division=0)
    print(f"\n{'Label':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    for label in TIER1_LABELS:
        r = report[label]
        print(f"{label:<12} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1-score']:>10.4f} {int(r['support']):>10,}")

    accuracy = report["accuracy"]
    print(f"\nOverall accuracy: {accuracy:.4f}")

    # Headline safety metric — accuracy alone is misleading at ~90% BENIGN.
    actual_benign = y_true == "BENIGN"
    false_positives = actual_benign & (y_pred != "BENIGN")
    benign_fpr = false_positives.sum() / actual_benign.sum() if actual_benign.sum() else 0.0
    print(f"BENIGN false-positive rate: {benign_fpr * 100:.4f}% "
          f"({false_positives.sum():,} of {actual_benign.sum():,} BENIGN rows wrongly flagged)")

    return {
        "confusion_matrix": cm,
        "report": report,
        "accuracy": accuracy,
        "benign_fpr": benign_fpr,
    }


# --------------------------------------------------------------------------
# 6. Save
# --------------------------------------------------------------------------

def write_summary(thresholds: dict, results: dict, summary_path: Path) -> None:
    lines = ["# Heuristic Baseline — PS26145\n"]

    lines.append("## Split")
    lines.append(f"- {int((1 - TEST_SIZE) * 100)}% train / {int(TEST_SIZE * 100)}% test, "
                  f"stratified by Label, random_state={RANDOM_STATE}\n")

    lines.append("## Thresholds (derived from TRAIN split, BENIGN rows only)")
    lines.append("| Threshold | Value |\n|---|---|")
    for name, value in thresholds.items():
        lines.append(f"| {name} | {value:,.4f} |")

    lines.append("\n## Test-set metrics")
    lines.append("| Label | Precision | Recall | F1 | Support |\n|---|---|---|---|---|")
    for label in TIER1_LABELS:
        r = results["report"][label]
        lines.append(f"| {label} | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1-score']:.4f} | {int(r['support']):,} |")

    lines.append(f"\n**Overall accuracy:** {results['accuracy']:.4f}")
    lines.append(f"\n**BENIGN false-positive rate:** {results['benign_fpr'] * 100:.4f}%")

    lines.append("\n## Confusion matrix (rows = actual, columns = predicted)")
    cm = results["confusion_matrix"]
    header = "| | " + " | ".join(TIER1_LABELS) + " |"
    sep = "|---" * (len(TIER1_LABELS) + 1) + "|"
    lines.append(header)
    lines.append(sep)
    for i, label in enumerate(TIER1_LABELS):
        row = f"| {label} | " + " | ".join(f"{cm[i][j]:,}" for j in range(len(TIER1_LABELS))) + " |"
        lines.append(row)

    summary_text = "\n".join(lines) + "\n"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary_text, encoding="utf-8")
    log.info("Summary written to %s", summary_path)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Heuristic baseline: split, threshold derivation, rule scoring, metrics."
    )
    parser.add_argument(
        "--input",
        default="data/processed/cicids2017_12_features_cleaned.csv",
        help="Path to the cleaned (raw, non-log1p) dataset CSV.",
    )
    parser.add_argument(
        "--summary-output",
        default="docs/heuristic_baseline_metrics.md",
        help="Path to write the Markdown metrics summary.",
    )
    args = parser.parse_args()

    df = load_data(args.input)
    train_df, test_df = split_stratified(df)

    train_df = add_iat_ratio(train_df)
    print_feature_insights(train_df)
    thresholds = derive_thresholds(train_df)

    y_pred = apply_rules(test_df, thresholds)
    results = evaluate(test_df, y_pred)

    write_summary(thresholds, results, Path(args.summary_output))


if __name__ == "__main__":
    main()