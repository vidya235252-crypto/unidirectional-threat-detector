"""
train_random_forest.py
========================
Random Forest training pipeline for the RF branch (Tier 1 ML detection —
C2/Bot, Port Scanning, DDoS — vs. Normal Traffic).

Pipeline (in order):
    1. Load the consolidated RF dataset, split features/target, and do a
       two-step stratified 70/15/15 Train/Validation/Test split.
    2. Train a class_weight='balanced' RandomForestClassifier on Train,
       then compare Train vs Validation metrics as an overfitting check
       (this is *not* a full hyperparameter search — see the note in
       Section 2 for why, and how to extend it if you have the compute
       budget).
    3. Run the finalized model once, on the untouched Test set, and print
       the classification report, labeled confusion matrix, and ranked
       feature importances.
    4. Serialize the model with joblib.

Usage
-----
    python train_random_forest.py

Reads   : data/processed/cleaned_network_data_rf.csv
Writes  : models/random_forest_model.joblib

Dependencies: pandas, numpy, scikit-learn, joblib
"""

from pathlib import Path
import sys
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

INPUT_PATH = Path("data/processed/cleaned_network_data_rf.csv")
MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "random_forest_model.joblib"

TARGET_COL = "Attack Type"

# Two-step split: first carve off 30% as temp, then split temp 50/50
# -> 70% train / 15% val / 15% test overall. Stratified at both steps
# so the 0.088%-prevalence Bots class stays proportional in all three.
TRAIN_SIZE = 0.70
VAL_SIZE = 0.15   # of the FULL dataset, not of the temp split
TEST_SIZE = 0.15  # of the FULL dataset
RANDOM_STATE = 42

# RandomForest hyperparameters. max_depth and min_samples_leaf are
# deliberately capped rather than left at defaults (unlimited depth):
# with class_weight='balanced' up-weighting the 0.088% Bots class by
# roughly 1/prevalence, an unconstrained tree will happily carve out
# single-sample leaves to chase that minority class in the training
# fold, which is exactly what the Train-vs-Validation comparison below
# is built to catch. The cap trades a small amount of training-set
# purity for a model that generalizes past this specific 2.2M-row draw.
RF_PARAMS = dict(
    n_estimators=300,
    max_depth=20,
    min_samples_leaf=5,
    class_weight="balanced",
    n_jobs=-1,
    random_state=RANDOM_STATE,
)

# Gap (Train metric - Validation metric) above which we print an
# explicit overfitting warning.
OVERFIT_GAP_THRESHOLD = 0.05


# --------------------------------------------------------------------------
# Step 1 — Load & three-way stratified split
# --------------------------------------------------------------------------

def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"[FATAL] Input file not found at '{path}'.")
    df = pd.read_csv(path)
    if TARGET_COL not in df.columns:
        sys.exit(f"[FATAL] Expected target column '{TARGET_COL}' not found in {path}.")
    print(f"[INFO] Loaded {len(df):,} rows x {df.shape[1]} columns from '{path}'.")
    return df


def three_way_split(df: pd.DataFrame):
    X = df.drop(columns=[TARGET_COL])
    y = df[TARGET_COL]

    # Step A: Train (70%) vs Temp (30% = Val + Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        train_size=TRAIN_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    # Step B: split Temp 50/50 -> Val (15% of full) / Test (15% of full)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=0.5,
        stratify=y_temp,
        random_state=RANDOM_STATE,
    )

    return X_train, X_val, X_test, y_train, y_val, y_test


def print_split_balance(y_train: pd.Series, y_val: pd.Series, y_test: pd.Series) -> None:
    """Proves the split is stratified correctly — every class, especially
    the 0.088%-prevalence Bots class, should show near-identical
    percentages across all three sets."""
    total = len(y_train) + len(y_val) + len(y_test)

    table = pd.DataFrame({
        "train_count": y_train.value_counts(),
        "val_count": y_val.value_counts(),
        "test_count": y_test.value_counts(),
    })
    table["train_pct"] = (y_train.value_counts(normalize=True) * 100).round(4)
    table["val_pct"] = (y_val.value_counts(normalize=True) * 100).round(4)
    table["test_pct"] = (y_test.value_counts(normalize=True) * 100).round(4)
    table = table[["train_count", "train_pct", "val_count", "val_pct", "test_count", "test_pct"]]
    table = table.sort_values("train_count", ascending=False)

    print("\n=== Three-Way Split — Row Counts & Class Balance ===")
    print(f"Total rows: {total:,}  |  "
          f"Train: {len(y_train):,} ({len(y_train)/total*100:.2f}%)  |  "
          f"Val: {len(y_val):,} ({len(y_val)/total*100:.2f}%)  |  "
          f"Test: {len(y_test):,} ({len(y_test)/total*100:.2f}%)")
    print(table.to_string())


# --------------------------------------------------------------------------
# Step 2 — Train + overfitting check via Train-vs-Validation comparison
# --------------------------------------------------------------------------

def train_and_check_overfitting(X_train, y_train, X_val, y_val) -> RandomForestClassifier:
    print(f"\n[INFO] Training RandomForestClassifier on {len(X_train):,} rows "
          f"with params: {RF_PARAMS}")

    # NOTE on hyperparameter tuning: a full GridSearchCV/RandomizedSearchCV
    # over this parameter space is deliberately NOT run here by default —
    # on a 2.2M-row training fold, a k-fold grid search multiplies training
    # time by (folds x candidates), which turns a ~1-2 minute fit into a
    # multi-hour job. Instead, this script fits once and uses the
    # Train-vs-Validation gap below as the tuning signal: if the gap is
    # large, tighten max_depth/min_samples_leaf and re-run; if it's small,
    # the current settings are not overfitting and you can stop here or
    # spend compute on a narrow search around them. A minimal starter grid
    # is left commented out for when you do have the budget:
    #
    # from sklearn.model_selection import GridSearchCV
    # param_grid = {"max_depth": [15, 20, 25], "min_samples_leaf": [2, 5, 10]}
    # search = GridSearchCV(RandomForestClassifier(class_weight="balanced",
    #                        n_jobs=-1, random_state=RANDOM_STATE),
    #                        param_grid, scoring="f1_macro", cv=3, n_jobs=-1)
    # search.fit(X_train, y_train)
    # model = search.best_estimator_

    start = time.time()
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(X_train, y_train)
    print(f"[INFO] Training completed in {time.time() - start:.1f}s.")

    train_pred = model.predict(X_train)
    val_pred = model.predict(X_val)

    train_acc = accuracy_score(y_train, train_pred)
    val_acc = accuracy_score(y_val, val_pred)
    train_f1 = f1_score(y_train, train_pred, average="macro")
    val_f1 = f1_score(y_val, val_pred, average="macro")

    print("\n=== Train vs. Validation — Overfitting Check ===")
    print(f"{'Metric':<20}{'Train':>12}{'Validation':>14}{'Gap':>10}")
    print(f"{'Accuracy':<20}{train_acc:>12.4f}{val_acc:>14.4f}{train_acc - val_acc:>10.4f}")
    print(f"{'Macro F1-Score':<20}{train_f1:>12.4f}{val_f1:>14.4f}{train_f1 - val_f1:>10.4f}")

    gap = train_f1 - val_f1
    if gap > OVERFIT_GAP_THRESHOLD:
        print(f"[WARNING] Train/Validation macro-F1 gap ({gap:.4f}) exceeds the "
              f"{OVERFIT_GAP_THRESHOLD} threshold — the model is likely overfitting "
              f"the training fold. Consider lowering max_depth, raising "
              f"min_samples_leaf, or reducing n_estimators.")
    else:
        print(f"[INFO] Train/Validation macro-F1 gap ({gap:.4f}) is within the "
              f"{OVERFIT_GAP_THRESHOLD} threshold — no strong overfitting signal.")

    # Validation-set detail, with the Bots row called out specifically
    # since it's the class most likely to be memorized rather than learned.
    val_report = classification_report(y_val, val_pred, output_dict=True, zero_division=0)
    if "Bots" in val_report:
        b = val_report["Bots"]
        print(f"[INFO] Validation — Bots class: precision={b['precision']:.4f}, "
              f"recall={b['recall']:.4f}, f1={b['f1-score']:.4f}, support={int(b['support'])}")

    return model


# --------------------------------------------------------------------------
# Step 3 — Final, single-pass evaluation on the untouched Test set
# --------------------------------------------------------------------------

def evaluate_on_test(model: RandomForestClassifier, X_test, y_test) -> None:
    print("\n" + "=" * 70)
    print("FINAL TEST SET EVALUATION (untouched — first and only use)")
    print("=" * 70)

    test_pred = model.predict(X_test)
    class_labels = sorted(y_test.unique())

    print("\n--- Classification Report ---")
    report_str = classification_report(y_test, test_pred, digits=4, zero_division=0)
    print(report_str)

    report_dict = classification_report(y_test, test_pred, output_dict=True, zero_division=0)
    if "Bots" in report_dict:
        b = report_dict["Bots"]
        print(f">>> Bots (0.088% of data) on Test — precision={b['precision']:.4f}, "
              f"recall={b['recall']:.4f}, f1={b['f1-score']:.4f}, "
              f"support={int(b['support'])} rows")

    print("\n--- Labeled Confusion Matrix (rows = actual, columns = predicted) ---")
    cm = confusion_matrix(y_test, test_pred, labels=class_labels)
    cm_df = pd.DataFrame(cm, index=[f"actual_{c}" for c in class_labels],
                          columns=[f"pred_{c}" for c in class_labels])
    print(cm_df.to_string())

    print("\n--- Ranked Feature Importance ---")
    importances = pd.Series(model.feature_importances_, index=X_test.columns)
    importances = importances.sort_values(ascending=False)
    importance_pct = (importances / importances.sum() * 100).round(2)
    imp_table = pd.DataFrame({"importance": importances.round(4), "importance_pct": importance_pct})
    print(imp_table.to_string())


# --------------------------------------------------------------------------
# Step 4 — Serialization
# --------------------------------------------------------------------------

def save_model(model: RandomForestClassifier, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    size_mb = path.stat().st_size / (1024 * 1024)
    print(f"\n[INFO] Model saved to '{path}' ({size_mb:.2f} MB).")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    df = load_data(INPUT_PATH)
    X_train, X_val, X_test, y_train, y_val, y_test = three_way_split(df)
    print_split_balance(y_train, y_val, y_test)

    model = train_and_check_overfitting(X_train, y_train, X_val, y_val)
    evaluate_on_test(model, X_test, y_test)
    save_model(model, MODEL_PATH)


if __name__ == "__main__":
    main()