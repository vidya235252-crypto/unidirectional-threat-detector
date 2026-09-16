"""
train_random_forest.py

Trains a Random Forest classifier on the cleaned CICIDS2017 (12-feature)
dataset for PS26145 Tier-1 threat classification: BENIGN, Bot, PortScan, DDoS.

Reproduces the EXACT 80/20 stratified split (random_state=42) used by
heuristic_baseline.py, so RF's metrics are directly comparable against the
heuristic baseline (docs/heuristic_baseline_metrics.md) on an apples-to-apples
basis -- that comparison is the entire point of this script (RF has to beat
the heuristic floor, not just "look good" on its own).

--------------------------------------------------------------------------
VERSION LOG (kept here so every change is traceable against past runs)
--------------------------------------------------------------------------
v1 -> results in docs/random_forest_metrics.md
     - class_weight='balanced', raw 11 CICIDS features, no engineered features
     - Bot F1 = 0.5750 (precision 0.4574, recall 0.7738) -- the weak class

v2 (THIS VERSION) -> results in docs/random_forest_metrics_v2.md
     CHANGE 1: added engineered feature `IAT_CV` = Flow IAT Std / Flow IAT
               Mean (coefficient of variation of inter-arrival time). Same
               ratio the heuristic Bot rule used for periodicity detection --
               handed to RF directly instead of making it reconstruct the
               ratio indirectly from the two raw IAT columns.
     CHANGE 2: class_weight switched from 'balanced' to an explicit dict
               {'BENIGN': 1, 'Bot': 15, 'PortScan': 1, 'DDoS': 1} -- pushes
               harder specifically on Bot without disturbing the three
               already near-perfect classes.
     GOAL: raise Bot's F1 above 0.5750 without degrading BENIGN precision /
     FPR or the other classes' near-perfect scores. v2's report explicitly
     restates v1's Bot numbers so the two are diffable at a glance.
--------------------------------------------------------------------------

Usage:
    python train_random_forest.py \
        --input data/processed/cicids2017_12_features_cleaned.csv \
        --output-metrics docs/random_forest_metrics_v2.md
"""

import argparse
import logging
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

LABEL_COL = "Label"
# Fixed class order -> keeps confusion matrix / metrics table layout identical
# to heuristic_baseline_metrics.md every run, regardless of pandas' sort order.
CLASS_ORDER = ["BENIGN", "Bot", "PortScan", "DDoS"]
RANDOM_STATE = 42
TEST_SIZE = 0.20

# CHANGE 2 (v2): explicit per-class weights, replacing class_weight='balanced'.
# Only Bot is pushed up -- the other three classes were already near-perfect
# in v1, so leaving them at 1 avoids disturbing what already worked.
CLASS_WEIGHTS = {"BENIGN": 1, "Bot": 15, "PortScan": 1, "DDoS": 1}

# v1 baseline numbers (from docs/random_forest_metrics.md), hardcoded here so
# the v2 report can print an explicit before/after comparison without needing
# to re-parse the old markdown file.
V1_RESULTS = {
    "accuracy": 0.9983,
    "benign_fpr": 0.001587,  # 0.1587%
    "per_class": {
        "BENIGN":   {"precision": 0.9997, "recall": 0.9984, "f1": 0.9991},
        "Bot":      {"precision": 0.4574, "recall": 0.7738, "f1": 0.5750},
        "PortScan": {"precision": 0.9876, "recall": 0.9997, "f1": 0.9936},
        "DDoS":     {"precision": 0.9986, "recall": 0.9996, "f1": 0.9991},
    },
}


def load_data(input_path: Path) -> pd.DataFrame:
    """Load the cleaned dataset and log shape / label breakdown."""
    logger.info("Loading cleaned dataset from %s", input_path)
    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()

    logger.info("Loaded %s rows, %s columns", f"{len(df):,}", df.shape[1])
    logger.info("Label breakdown:")
    for label, count in df[LABEL_COL].value_counts().items():
        logger.info("  %-10s %10s rows (%.4f%%)", label, f"{count:,}", 100 * count / len(df))

    missing = set(CLASS_ORDER) - set(df[LABEL_COL].unique())
    if missing:
        raise ValueError(f"Expected classes not found in data: {missing}")

    return df


def add_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    CHANGE 1 (v2): add IAT_CV = Flow IAT Std / Flow IAT Mean.

    This is the exact coefficient-of-variation ratio the heuristic Bot rule
    used for periodicity detection (low CV = very regular timing = likely
    C2 beaconing). RF could previously only approximate this relationship
    indirectly by splitting separately on 'Flow IAT Mean' and 'Flow IAT Std'
    across different trees -- handing it the ratio directly as one column
    makes that signal explicit and easier for trees to split on cleanly.

    Guard: when Flow IAT Mean == 0, the ratio is undefined. Unlike the
    heuristic rule (which could just let `NaN < threshold` evaluate False),
    RandomForestClassifier CANNOT fit on raw NaN values -- it raises a
    ValueError. So undefined rows get an explicit out-of-range sentinel
    (-1) instead of NaN or 0: 0 would misleadingly look like "perfectly
    regular timing" (the exact Bot signature), whereas -1 can never occur
    naturally (CV is a ratio of two non-negative values) and lets the trees
    learn "-1 means undefined" as its own distinct split, if useful.

    NOTE: this is computed in-memory only, on this run's DataFrame. It is
    NEVER written back to cicids2017_12_features_cleaned.csv -- the shared
    cleaned CSV stays untouched and reusable by every other script (Isolation
    Forest does not need this feature -- see Change Log in the module
    docstring).
    """
    logger.info("Adding engineered feature: IAT_CV = Flow IAT Std / Flow IAT Mean")
    df = df.copy()
    mean = df["Flow IAT Mean"]
    std = df["Flow IAT Std"]

    undefined_mask = mean == 0
    iat_cv = pd.Series(index=df.index, dtype="float64")
    iat_cv[~undefined_mask] = std[~undefined_mask] / mean[~undefined_mask]
    iat_cv[undefined_mask] = -1.0  # sentinel: undefined, never occurs naturally
    df["IAT_CV"] = iat_cv

    n_undefined = int(undefined_mask.sum())
    logger.info(
        "IAT_CV computed for %s rows; %s rows set to sentinel -1 (Flow IAT Mean == 0)",
        f"{len(df) - n_undefined:,}", f"{n_undefined:,}",
    )
    return df


def reproduce_split(df: pd.DataFrame):
    """
    Reproduce the EXACT train/test split used by heuristic_baseline.py:
        train_test_split(df, test_size=0.20, stratify=df['Label'], random_state=42)

    This identical split is what makes "RF beat the heuristic baseline" a
    valid claim to an evaluator -- both models are scored on the same rows.
    """
    logger.info("Reproducing 80/20 stratified split (random_state=%d)", RANDOM_STATE)
    train_df, test_df = train_test_split(
        df,
        test_size=TEST_SIZE,
        stratify=df[LABEL_COL],
        random_state=RANDOM_STATE,
    )
    logger.info("Train: %s rows | Test: %s rows", f"{len(train_df):,}", f"{len(test_df):,}")

    logger.info("Test-split label breakdown:")
    for label, count in test_df[LABEL_COL].value_counts().items():
        logger.info("  %-10s %10s rows (%.4f%%)", label, f"{count:,}", 100 * count / len(test_df))

    feature_cols = [c for c in df.columns if c != LABEL_COL]
    X_train, y_train = train_df[feature_cols], train_df[LABEL_COL]
    X_test, y_test = test_df[feature_cols], test_df[LABEL_COL]
    return X_train, X_test, y_train, y_test, feature_cols


def train_random_forest(X_train, y_train) -> RandomForestClassifier:
    """
    Train on RAW (non-log1p) feature values -- RF splits on threshold
    comparisons, so it's invariant to monotonic transforms like log1p.
    (Isolation Forest needs log1p; RF explicitly does not -- Decision #6.)

    CHANGE 2 (v2): class_weight is now the explicit dict CLASS_WEIGHTS
    instead of the string 'balanced'. 'balanced' auto-computes weights
    inversely proportional to class frequency -- for Bot (0.09% of rows)
    that works out to a very large automatic weight, which v1's results
    suggest already pushed hard on Bot's recall (0.7738) but at a real cost
    to Bot's precision (0.4574, i.e. more than half of "Bot" alerts were
    false alarms). CLASS_WEIGHTS applies a smaller, deliberately chosen
    weight (15) to Bot only, leaving BENIGN/PortScan/DDoS at 1 so their
    already near-perfect v1 scores aren't disturbed.
    """
    logger.info("Training RandomForestClassifier with explicit class_weight=%s", CLASS_WEIGHTS)
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight=CLASS_WEIGHTS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    logger.info("Training complete: %d trees, %d input features", model.n_estimators, model.n_features_in_)
    return model


def evaluate_model(model, X_test, y_test):
    """Score the trained model on the held-out test split, same metrics as the heuristic baseline."""
    logger.info("Scoring on test split")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, labels=CLASS_ORDER, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred, labels=CLASS_ORDER)

    # BENIGN false-positive rate = actual-BENIGN rows predicted as anything
    # else, divided by all actual-BENIGN rows. Same definition used in
    # heuristic_baseline_metrics.md -> the two numbers are directly comparable.
    benign_idx = CLASS_ORDER.index("BENIGN")
    benign_row = cm[benign_idx]
    benign_total = int(benign_row.sum())
    benign_fp = benign_total - int(benign_row[benign_idx])
    benign_fpr = benign_fp / benign_total if benign_total else 0.0

    logger.info("Accuracy: %.4f", accuracy)
    logger.info("BENIGN false-positive rate: %.4f%%", benign_fpr * 100)
    for i, label in enumerate(CLASS_ORDER):
        logger.info(
            "  %-10s precision=%.4f recall=%.4f f1=%.4f support=%d",
            label, precision[i], recall[i], f1[i], support[i],
        )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "support": support,
        "confusion_matrix": cm,
        "benign_fpr": benign_fpr,
    }


def get_top_features(model, feature_cols, top_n: int = 5):
    """
    Global feature importances (Gini importance), sorted descending.

    IMPORTANT DISTINCTION for the write-up: this is model-level "which
    features matter overall" -- it is NOT the same as the frozen Inference
    Response contract's per-flow `top_features` field, which must name the
    2 features that drove ONE specific prediction. That needs a per-sample
    explanation method (per-tree decision path, or SHAP), not
    .feature_importances_. Flag this gap before wiring the real inference
    service on Day 6.
    """
    importances = model.feature_importances_
    ranked = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    logger.info("Top %d global feature importances:", top_n)
    for name, score in ranked[:top_n]:
        logger.info("  %-25s %.4f", name, score)
    return ranked


def write_metrics_report(output_path: Path, split_sizes, model, metrics, ranked_features, feature_cols):
    """Write a markdown report in the same format as heuristic_baseline_metrics.md,
    plus a Run Configuration block and an explicit v1-vs-v2 comparison so the
    improvement (or regression) from each change is visible without manually
    diffing two separate files."""
    lines = []
    lines.append("# Random Forest v2 — PS26145\n")

    lines.append("## Changes vs. v1 (docs/random_forest_metrics.md)")
    lines.append("1. **Added engineered feature `IAT_CV`** = Flow IAT Std / Flow IAT Mean "
                  "(periodicity signal, same ratio the heuristic Bot rule used).")
    lines.append(f"2. **class_weight changed** from `'balanced'` to explicit dict `{CLASS_WEIGHTS}`.\n")

    lines.append("## Split")
    lines.append(f"- 80% train / 20% test, stratified by Label, random_state={RANDOM_STATE}")
    lines.append(f"- Train rows: {split_sizes[0]:,} | Test rows: {split_sizes[1]:,}\n")

    lines.append("## Model / Run configuration")
    lines.append(
        f"- RandomForestClassifier, n_estimators={model.n_estimators}, "
        f"class_weight={CLASS_WEIGHTS}, random_state={RANDOM_STATE}"
    )
    lines.append("- Trained on raw (non-log1p) feature values")
    lines.append(f"- Feature columns ({len(feature_cols)}): {', '.join(feature_cols)}")
    lines.append("  (`IAT_CV` is the new engineered feature — not present in the v1 run)\n")

    lines.append("## Before / After comparison (v1 → v2)")
    lines.append("| Metric | v1 | v2 | Change |")
    lines.append("|---|---|---|---|")
    acc_delta = metrics["accuracy"] - V1_RESULTS["accuracy"]
    fpr_delta = (metrics["benign_fpr"] - V1_RESULTS["benign_fpr"]) * 100
    lines.append(f"| Overall accuracy | {V1_RESULTS['accuracy']:.4f} | {metrics['accuracy']:.4f} | "
                 f"{acc_delta:+.4f} |")
    lines.append(f"| BENIGN false-positive rate | {V1_RESULTS['benign_fpr']*100:.4f}% | "
                 f"{metrics['benign_fpr']*100:.4f}% | {fpr_delta:+.4f} pp |")
    for i, label in enumerate(CLASS_ORDER):
        v1c = V1_RESULTS["per_class"][label]
        lines.append(f"| {label} — Precision | {v1c['precision']:.4f} | {metrics['precision'][i]:.4f} | "
                     f"{metrics['precision'][i]-v1c['precision']:+.4f} |")
        lines.append(f"| {label} — Recall | {v1c['recall']:.4f} | {metrics['recall'][i]:.4f} | "
                     f"{metrics['recall'][i]-v1c['recall']:+.4f} |")
        lines.append(f"| {label} — F1 | {v1c['f1']:.4f} | {metrics['f1'][i]:.4f} | "
                     f"{metrics['f1'][i]-v1c['f1']:+.4f} |")
    lines.append(
        "\n> Positive Change = improvement for Precision/Recall/F1/Accuracy. "
        "Positive Change on BENIGN FPR = MORE false positives (worse).\n"
    )

    lines.append("## Test-set metrics (v2, full detail)")
    lines.append("| Label | Precision | Recall | F1 | Support |")
    lines.append("|---|---|---|---|---|")
    for i, label in enumerate(CLASS_ORDER):
        lines.append(
            f"| {label} | {metrics['precision'][i]:.4f} | {metrics['recall'][i]:.4f} | "
            f"{metrics['f1'][i]:.4f} | {metrics['support'][i]} |"
        )
    lines.append(f"\n**Overall accuracy:** {metrics['accuracy']:.4f}\n")
    lines.append(f"**BENIGN false-positive rate:** {metrics['benign_fpr'] * 100:.4f}%\n")

    lines.append("## Confusion matrix (rows = actual, columns = predicted)")
    lines.append("| | " + " | ".join(CLASS_ORDER) + " |")
    lines.append("|---" * (len(CLASS_ORDER) + 1) + "|")
    cm = metrics["confusion_matrix"]
    for i, label in enumerate(CLASS_ORDER):
        lines.append(f"| {label} | " + " | ".join(str(v) for v in cm[i]) + " |")

    lines.append("\n## Top global feature importances (Gini)")
    lines.append("| Feature | Importance |")
    lines.append("|---|---|")
    for name, score in ranked_features:
        lines.append(f"| {name} | {score:.4f} |")
    lines.append(
        "\n> Note: these are GLOBAL importances, not the per-flow `top_features` "
        "required by the frozen Inference Response contract — see the docstring "
        "in `get_top_features()`."
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Metrics report written to %s", output_path)


def main():
    parser = argparse.ArgumentParser(description="Train Random Forest v2 for PS26145 Tier-1 threat classification")
    parser.add_argument("--input", type=Path, default=Path("data/processed/cicids2017_12_features_cleaned.csv"))
    # Default filename deliberately differs from v1's docs/random_forest_metrics.md
    # so the original report is never overwritten -- both stay on disk for diffing.
    parser.add_argument("--output-metrics", type=Path, default=Path("docs/random_forest_metrics_v2.md"))
    args = parser.parse_args()

    df = load_data(args.input)
    df = add_engineered_features(df)  # CHANGE 1: adds IAT_CV column
    X_train, X_test, y_train, y_test, feature_cols = reproduce_split(df)
    model = train_random_forest(X_train, y_train)  # CHANGE 2: explicit CLASS_WEIGHTS used inside
    metrics = evaluate_model(model, X_test, y_test)
    ranked_features = get_top_features(model, feature_cols)
    write_metrics_report(
        args.output_metrics, (len(X_train), len(X_test)), model, metrics, ranked_features, feature_cols
    )

    logger.info("Done.")


if __name__ == "__main__":
    main()