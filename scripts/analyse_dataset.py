"""
analyse_dataset.py
Quick exploratory analysis of the CICIDS2017 dataset before training.
Run this BEFORE model training to understand shape, quality issues, and class balance.

Usage:
    python analyse_dataset.py --path data/raw/<your_file>.csv
"""

import argparse
import numpy as np
import pandas as pd

pd.set_option("display.max_rows", 100)
pd.set_option("display.width", 120)


def load_data(path: str) -> pd.DataFrame:
    """Load CSV. Strip whitespace from column names — CICIDS2017 files often have leading spaces."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def report_shape(df: pd.DataFrame):
    """Basic size info — first thing an evaluator will ask."""
    print("\n=== SHAPE ===")
    print(f"Rows: {df.shape[0]:,}  |  Columns: {df.shape[1]}")
    print(f"Memory usage: {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")


def report_dtypes(df: pd.DataFrame):
    """Column data types — confirms what's numeric vs categorical (Label)."""
    print("\n=== DATA TYPES (count per type) ===")
    print(df.dtypes.value_counts())


def report_nulls(df: pd.DataFrame):
    """Null counts per column — only prints columns that actually have nulls."""
    print("\n=== NULL VALUES ===")
    nulls = df.isnull().sum()
    nulls = nulls[nulls > 0]
    if nulls.empty:
        print("No null values found.")
    else:
        print(nulls.sort_values(ascending=False))


def report_infinite(df: pd.DataFrame):
    """Infinite values — common in CICIDS2017 rate columns (Flow Bytes/s, Flow Packets/s)."""
    print("\n=== INFINITE VALUES ===")
    numeric_df = df.select_dtypes(include=[np.number])
    inf_counts = np.isinf(numeric_df).sum()
    inf_counts = inf_counts[inf_counts > 0]
    if inf_counts.empty:
        print("No infinite values found.")
    else:
        print(inf_counts.sort_values(ascending=False))


def report_duplicates(df: pd.DataFrame):
    """Exact duplicate rows — inflate training data if not removed."""
    print("\n=== DUPLICATE ROWS ===")
    dup_count = df.duplicated().sum()
    print(f"Duplicate rows: {dup_count:,} ({dup_count / len(df) * 100:.2f}% of data)")


def report_label_distribution(df: pd.DataFrame, label_col: str = "Label"):
    """Class balance — THE most important check before training. Shows benign vs attack skew."""
    print("\n=== ATTACK TYPE DISTRIBUTION ===")
    if label_col not in df.columns:
        print(f"Column '{label_col}' not found. Available columns: {list(df.columns)[:10]}...")
        return
    counts = df[label_col].value_counts()
    percentages = df[label_col].value_counts(normalize=True) * 100
    summary = pd.DataFrame({"count": counts, "percent": percentages.round(2)})
    print(summary)


def report_basic_stats(df: pd.DataFrame):
    """Descriptive stats (mean/std/min/max) — spot obviously broken columns (e.g. negative durations)."""
    print("\n=== BASIC STATISTICS (numeric columns) ===")
    print(df.describe().T[["mean", "std", "min", "max"]])


def report_zero_variance_columns(df: pd.DataFrame):
    """Columns where every value is the same — useless for training, safe to drop."""
    print("\n=== ZERO-VARIANCE COLUMNS ===")
    numeric_df = df.select_dtypes(include=[np.number])
    zero_var = numeric_df.columns[numeric_df.nunique() <= 1].tolist()
    print(zero_var if zero_var else "None found.")


def report_extended_analysis(df: pd.DataFrame, label_col: str = "Label"):
    """
    Follow-up analysis, run AFTER the checks above have flagged issues.
    Answers: which labels are affected by duplicates / inf values / nulls,
    and whether any class is too small to survive a stratified split.
    """
    print("\n" + "=" * 60)
    print("EXTENDED ANALYSIS: LABEL BREAKDOWN OF FLAGGED ISSUES")
    print("=" * 60)

    if label_col not in df.columns:
        print(f"Column '{label_col}' not found — skipping extended analysis.")
        return

    # --- a. Label distribution within the duplicate rows -----------------
    # keep='first' matches the ORIGINAL duplicate count from report_duplicates()
    # (flags only the "extra" copies, not the first occurrence of each).
    print(f"\n=== a. {label_col} DISTRIBUTION — DUPLICATE ROWS (extras only) ===")
    dup_extras = df[df.duplicated(keep='first')]
    print(dup_extras[label_col].value_counts())
    print(f"Total: {len(dup_extras)} rows "
          f"({len(dup_extras) / len(df) * 100:.2f}% of dataset)")

    print("\n(Sanity check — full duplicate groups incl. originals:)")
    dup_full_groups = df[df.duplicated(keep=False)]
    print(dup_full_groups[label_col].value_counts())

    # --- b. Label distribution within the inf rows ------------------------
    print(f"\n=== b. {label_col} DISTRIBUTION — INF ROWS (Flow Bytes/s or Flow Packets/s) ===")
    if "Flow Bytes/s" in df.columns and "Flow Packets/s" in df.columns:
        inf_mask = np.isinf(df["Flow Bytes/s"]) | np.isinf(df["Flow Packets/s"])
        inf_rows = df[inf_mask]
        print(inf_rows[label_col].value_counts())
        print(f"Total: {len(inf_rows)} rows "
              f"({len(inf_rows) / len(df) * 100:.4f}% of dataset)")
    else:
        print("Flow Bytes/s or Flow Packets/s column not found — skipping.")

    # --- c. Null row count --------------------------------------------
    print(f"\n=== c. NULL ROWS — COUNT & {label_col} BREAKDOWN ===")
    null_mask = df.isnull().any(axis=1)
    null_count = null_mask.sum()
    print(f"Total rows with at least one null value: {null_count}")

    if null_count > 0:
        null_labels = df.loc[null_mask, label_col].value_counts()
        print(f"\n{label_col} breakdown of null rows:")
        print(null_labels)

        if "Bot" in null_labels.index:
            print(f"\n⚠ {null_labels['Bot']} null row(s) belong to the Bot class — "
                  f"do NOT drop without inspecting these individually first.")
    else:
        print("No null rows found.")

    # --- d. Class distribution summary for imbalance planning --------------
    print(f"\n=== d. {label_col} DISTRIBUTION — FOR EVALUATION SPLIT & IMBALANCE STRATEGY ===")
    label_counts = df[label_col].value_counts()
    label_pct = df[label_col].value_counts(normalize=True) * 100
    summary = pd.DataFrame({"count": label_counts, "percent": label_pct.round(4)})
    print(summary)

    too_small = summary[summary["count"] < 50]
    if not too_small.empty:
        print("\n⚠ Classes with <50 rows — unreliable for stratified split, "
              "decide explicitly whether to merge, exclude, or oversample:")
        print(too_small)

    summary.to_csv("data/processed/label_distribution_summary.csv")
    print("\nSaved: data/processed/label_distribution_summary.csv")


def main():
    parser = argparse.ArgumentParser(description="Analyse CICIDS2017 dataset before training.")
    parser.add_argument("--path", required=True, help="Path to the CSV file to analyse")
    parser.add_argument("--label_col", default="Label", help="Name of the label column")
    args = parser.parse_args()

    df = load_data(args.path)

    # Run each check in order — output is meant to be read top to bottom, or copied into your report
    report_shape(df)
    report_dtypes(df)
    report_nulls(df)
    report_infinite(df)
    report_duplicates(df)
    report_label_distribution(df, args.label_col)
    report_basic_stats(df)
    report_zero_variance_columns(df)
    report_extended_analysis(df, args.label_col)


if __name__ == "__main__":
    main()