"""
check_negative_values.py

Diagnostic-only script for PS26145 (unidirectional-threat-detector).

Purpose
-------
Before deciding how to handle negative values in the columns slated for a
log1p transform, this script reports exactly how many rows are affected,
what fraction of the dataset that is, and which attack labels those rows
belong to. It does NOT modify or write any file — read-only inspection.

Usage
-----
    python check_negative_values.py --input data/processed/cicids2017_12_features.csv

Style matches scripts/analyse_dataset.py: small documented functions,
called in order from main(), argparse for the input path.
"""

import argparse
import logging

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Every column slated for the log1p transform (Decision #6). We check all of
# them, not just the two flagged in the report stats, since any of them
# could hide the same exporter artifact.
LOG1P_CANDIDATE_COLUMNS = [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Average Packet Size",
]


def load_data(input_path: str) -> pd.DataFrame:
    """Load the CSV and normalise column names (strip whitespace)."""
    log.info("Loading dataset from %s", input_path)
    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()
    log.info("Loaded %s rows, %s columns", f"{len(df):,}", df.shape[1])
    return df


def check_column_for_negatives(df: pd.DataFrame, column: str) -> None:
    """Report negative-value stats and label breakdown for one column."""
    if column not in df.columns:
        log.warning("Column '%s' not found in dataset — skipping", column)
        return

    total_rows = len(df)
    series = df[column]

    # Only finite values count here — inf/-inf and NaN are separate,
    # already-handled issues (Decisions #3 and the null-discrepancy fix).
    finite_mask = series.notna() & ~series.isin([float("inf"), float("-inf")])
    negative_mask = finite_mask & (series < 0)

    negative_count = int(negative_mask.sum())
    pct = (negative_count / total_rows) * 100 if total_rows else 0.0

    print(f"\n--- {column} ---")
    print(f"Negative (finite) values: {negative_count:,} rows ({pct:.4f}% of dataset)")

    if negative_count == 0:
        print("No negative values found.")
        return

    neg_series = series[negative_mask]
    print(f"Min value: {neg_series.min():,.4f}")
    print(f"Max (least negative) value: {neg_series.max():,.4f}")
    print(f"Median: {neg_series.median():,.4f}")

    if "Label" in df.columns:
        breakdown = df.loc[negative_mask, "Label"].value_counts()
        print("Label breakdown of negative rows:")
        for label, count in breakdown.items():
            class_total = (df["Label"] == label).sum()
            class_pct = (count / class_total) * 100 if class_total else 0.0
            print(f"  {label:30s} {count:>8,}  ({class_pct:.4f}% of that class)")
    else:
        log.warning("'Label' column not found — cannot show per-class breakdown")


def check_row_overlap(df: pd.DataFrame, columns: list) -> None:
    """Report how many rows have negative values in MORE than one column.

    This matters for deciding drop-vs-clip: if the same rows are already
    getting dropped by another step (e.g. negative Flow Duration), the
    negative-value issue here may already be shrinking or resolving itself.
    """
    finite_neg_masks = {}
    for column in columns:
        if column not in df.columns:
            continue
        series = df[column]
        finite_mask = series.notna() & ~series.isin([float("inf"), float("-inf")])
        finite_neg_masks[column] = finite_mask & (series < 0)

    if not finite_neg_masks:
        return

    combined = pd.DataFrame(finite_neg_masks)
    any_negative = combined.any(axis=1)
    multi_negative = combined.sum(axis=1) >= 2

    print("\n--- Overlap across log1p target columns ---")
    print(f"Rows with a negative value in AT LEAST ONE target column: {int(any_negative.sum()):,}")
    print(f"Rows with negative values in TWO OR MORE target columns: {int(multi_negative.sum()):,}")

    if "Flow Duration" in df.columns:
        neg_duration = df["Flow Duration"] < 0
        overlap_with_neg_duration = int((any_negative & neg_duration).sum())
        print(
            f"Rows with negative log1p-target value AND negative Flow Duration: "
            f"{overlap_with_neg_duration:,} "
            f"(out of {int(neg_duration.sum()):,} total negative-Flow-Duration rows)"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report negative-value counts/label breakdown in log1p target columns (read-only)."
    )
    parser.add_argument(
        "--input",
        default="data/processed/cicids2017_12_features.csv",
        help="Path to the raw/uncleaned dataset CSV.",
    )
    args = parser.parse_args()

    df = load_data(args.input)

    print("\n" + "=" * 70)
    print("NEGATIVE VALUE CHECK — log1p target columns (Decision #6)")
    print("=" * 70)

    for column in LOG1P_CANDIDATE_COLUMNS:
        check_column_for_negatives(df, column)

    check_row_overlap(df, LOG1P_CANDIDATE_COLUMNS)

    print("\n" + "=" * 70)
    print("Done. No files were modified — this script is read-only.")
    print("=" * 70)


if __name__ == "__main__":
    main()