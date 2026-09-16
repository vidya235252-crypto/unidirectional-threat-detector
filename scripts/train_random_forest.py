"""
train_random_forest.py

Trains a Random Forest classifier on the cleaned CICIDS2017 (12-feature)
dataset for PS26145 Tier-1 threat classification: BENIGN, Bot, PortScan, DDoS.

Reproduces the EXACT 80/20 stratified split (random_state=42) used by
heuristic_baseline.py, so RF's metrics are directly comparable against the
heuristic baseline (docs/heuristic_baseline_metrics.md) on an apples-to-apples
basis -- that comparison is the entire point of this script (RF has to beat
the heuristic floor, not just "look good" on its own).

Usage:
    python train_random_forest.py \
        --input data/processed/cicids2017_12_features_cleaned.csv \
        --output-metrics docs/random_forest_metrics.md
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

    class_weight='balanced' addresses the extreme imbalance
    (BENIGN 89.86% vs Bot 0.09%) -- Decision #5. Without it, RF could hit
    ~90% accuracy by just always predicting BENIGN while being useless
    as a detector.
    """
    logger.info("Training RandomForestClassifier (class_weight='balanced')")
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
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


def write_metrics_report(output_path: Path, split_sizes, model, metrics, ranked_features):
    """Write a markdown report in the same format as heuristic_baseline_metrics.md."""
    lines = []
    lines.append("# Random Forest — PS26145\n")

    lines.append("## Split")
    lines.append(f"- 80% train / 20% test, stratified by Label, random_state={RANDOM_STATE}")
    lines.append(f"- Train rows: {split_sizes[0]:,} | Test rows: {split_sizes[1]:,}\n")

    lines.append("## Model")
    lines.append(
        f"- RandomForestClassifier, n_estimators={model.n_estimators}, "
        f"class_weight='balanced', random_state={RANDOM_STATE}"
    )
    lines.append("- Trained on raw (non-log1p) feature values\n")

    lines.append("## Test-set metrics")
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
    parser = argparse.ArgumentParser(description="Train Random Forest for PS26145 Tier-1 threat classification")
    parser.add_argument("--input", type=Path, default=Path("data/processed/cicids2017_12_features_cleaned.csv"))
    parser.add_argument("--output-metrics", type=Path, default=Path("docs/random_forest_metrics.md"))
    args = parser.parse_args()

    df = load_data(args.input)
    X_train, X_test, y_train, y_test, feature_cols = reproduce_split(df)
    model = train_random_forest(X_train, y_train)
    metrics = evaluate_model(model, X_test, y_test)
    ranked_features = get_top_features(model, feature_cols)
    write_metrics_report(args.output_metrics, (len(X_train), len(X_test)), model, metrics, ranked_features)

    logger.info("Done.")


if __name__ == "__main__":
    main()