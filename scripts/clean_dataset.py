"""
clean_dataset.py

PS26145 — unidirectional-threat-detector
Applies Decisions #1-8 (agreed in dataset-cleaning review) to the raw
CICIDS2017 12-feature CSV and writes a cleaned copy for training.

Style matches scripts/analyse_dataset.py: small documented functions,
called in order from main(), argparse for --input/--output paths.

Decisions implemented, in execution order
-------------------------------------------
1. Drop the single stray row where every column is null (multi-day CSV
   merge artifact).
2. Impute Flow Bytes/s (and Flow Packets/s, if present) NaN -> 0. These
   are 0/0 cases (zero bytes over zero duration) — a different root
   cause from the infinite-value rows below (Decision #4 in the
   cleaning-review conversation; distinct from original Decision #4's
   "1 stray row").
3. Drop rows with infinite Flow Bytes/s or Flow Packets/s (x/0 cases,
   spread thin across classes, not concentrated in Bot — safe to drop
   rather than impute).
4. Drop rows with negative Flow Duration (confirmed 100% BENIGN). As a
   verified side effect, this also removes every row with a negative
   value in Flow Bytes/s or Flow IAT Mean — confirmed via
   check_negative_values.py before this script was written, so no
   separate clipping step is needed for Decision #6's log1p prep.
5. Drop duplicate rows (keep first occurrence). Bot-class impact
   verified negligible (17 of 1,966 rows, 0.86%) before this was
   approved.
6. Filter to Tier-1 scope only: BENIGN, Bot, PortScan, DDoS.
   DoS Hulk is explicitly EXCLUDED: it's an HTTP-layer request flood
   (repeated GET/POST), not a SYN flood or a true DDoS mechanism, so it
   doesn't belong in the Tier-1 "SYN flood/volumetric" scenario. All
   other CICIDS2017 labels (FTP-Patator, SSH-Patator, the Web Attack
   subtypes, Heartbleed, Infiltration, DoS GoldenEye, DoS slowloris,
   DoS Slowhttptest, DoS Hulk) are out of architecture scope and
   dropped rather than bucketed. Original label names are KEPT
   (no merging into a unified "SYN_FLOOD_VOLUMETRIC" label at this
   stage — that happens later, at training time, if at all).
7. log1p is intentionally NOT applied here. It's deferred to the
   Isolation Forest training script, since it was only ever needed to
   stop IF's random splits from being distorted by heavy tails —
   Random Forest doesn't need it (invariant to monotonic transforms),
   and a raw-value cleaned CSV is what a live flow from the ingestion
   engine will actually look like, so this file stays consistent with
   that reality. Apply log1p to LOG1P_COLUMNS (see list further down,
   kept here for reference) right before fitting Isolation Forest —
   not before.

Not implemented here (training-time concerns, not data-cleaning):
  - Decision #7 (class_weight='balanced' for Random Forest)
  - Decision #7 (Isolation Forest trains on benign rows only, with NO
    balancing treatment applied to its training subset)
These are model-training parameters, not row/column transforms, and
belong in the training script, not this cleaning script.

Usage
-----
    python clean_dataset.py \\
        --input data/processed/cicids2017_12_features.csv \\
        --output data/processed/cicids2017_12_features_cleaned.csv
"""

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

LABEL_COL = "Label"

# Decision #6: Tier-1 scope. Everything else gets dropped, not bucketed.
# DoS Hulk is deliberately excluded — it's an HTTP-layer request flood,
# not a SYN flood / true DDoS mechanism, so it doesn't fit the Tier-1
# "SYN flood/volumetric" scenario. DDoS is the sole volumetric class.
TIER1_LABELS = ["BENIGN", "Bot", "PortScan", "DDoS"]

# Decision #2 (cleaning-review): 0/0 NaN case, distinct from the x/0 inf case.
ZERO_DIVISION_NAN_COLUMNS = ["Flow Bytes/s", "Flow Packets/s"]

# Reference only — NOT applied in this script. Apply log1p to these
# columns in the Isolation Forest training script, right before .fit(),
# not here. Kept here so the column list has one source of truth.
LOG1P_COLUMNS = [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Average Packet Size",
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def load_data(input_path: str) -> pd.DataFrame:
    """Load the raw CSV and normalise column names."""
    log.info("Loading dataset from %s", input_path)
    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()
    log.info("Loaded %s rows, %s columns", f"{len(df):,}", df.shape[1])
    return df


def log_label_breakdown(df: pd.DataFrame, title: str, level=logging.INFO) -> None:
    """Print a label value_counts breakdown with percentages."""
    if LABEL_COL not in df.columns or df.empty:
        return
    total = len(df)
    counts = df[LABEL_COL].value_counts()
    log.log(level, "%s (%s rows):", title, f"{total:,}")
    for label, count in counts.items():
        pct = (count / total) * 100
        log.log(level, "    %-28s %10s  (%.4f%%)", label, f"{count:,}", pct)


def _step_header(step_name: str) -> None:
    log.info("=" * 70)
    log.info("STEP: %s", step_name)
    log.info("=" * 70)


# --------------------------------------------------------------------------
# Cleaning steps (Decisions #1-8, in execution order)
# --------------------------------------------------------------------------

def drop_fully_null_row(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: drop the single stray row where every column is null."""
    _step_header("Drop fully-null stray row")
    fully_null_mask = df.isna().all(axis=1)
    n_dropped = int(fully_null_mask.sum())
    before = len(df)

    if n_dropped == 0:
        log.info("No fully-null rows found. Nothing dropped.")
        return df

    log.info("Dropping %s fully-null row(s) out of %s (%.6f%%)",
              n_dropped, f"{before:,}", (n_dropped / before) * 100)
    cleaned = df.loc[~fully_null_mask].reset_index(drop=True)
    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def impute_zero_division_nan(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: fill remaining NaN in rate columns (0/0 case) with 0."""
    _step_header("Impute 0/0 NaN in rate columns -> 0")
    cleaned = df.copy()

    for col in ZERO_DIVISION_NAN_COLUMNS:
        if col not in cleaned.columns:
            log.warning("Column '%s' not found — skipping", col)
            continue
        n_nan = int(cleaned[col].isna().sum())
        if n_nan == 0:
            log.info("%-20s: no remaining NaN values.", col)
            continue
        pct = (n_nan / len(cleaned)) * 100
        log.info("%-20s: imputing %s NaN values -> 0 (%.4f%% of dataset)",
                  col, f"{n_nan:,}", pct)
        nan_mask = cleaned[col].isna()
        log_label_breakdown(cleaned.loc[nan_mask], f"  Label breakdown of imputed '{col}' rows")
        cleaned[col] = cleaned[col].fillna(0)

    # Defensive check: any other column with unexpected remaining NaN gets
    # flagged loudly and dropped rather than silently imputed, since that
    # would be an assumption outside the agreed decisions.
    remaining_nan_cols = [c for c in cleaned.columns if cleaned[c].isna().any()]
    if remaining_nan_cols:
        log.warning("Unexpected remaining NaN in columns: %s", remaining_nan_cols)
        before = len(cleaned)
        unexpected_mask = cleaned[remaining_nan_cols].isna().any(axis=1)
        n_dropped = int(unexpected_mask.sum())
        log.warning("Dropping %s row(s) with unexpected NaN (%.6f%%) — "
                     "review this, it wasn't part of the agreed decisions.",
                     n_dropped, (n_dropped / before) * 100)
        log_label_breakdown(cleaned.loc[unexpected_mask], "  Label breakdown", level=logging.WARNING)
        cleaned = cleaned.loc[~unexpected_mask].reset_index(drop=True)

    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def drop_infinite_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: drop rows with infinite Flow Bytes/s or Flow Packets/s (x/0 case)."""
    _step_header("Drop infinite-value rows (Flow Bytes/s, Flow Packets/s)")
    numeric_cols = ["Flow Bytes/s", "Flow Packets/s"]
    present_cols = [c for c in numeric_cols if c in df.columns]

    inf_mask = pd.Series(False, index=df.index)
    for col in present_cols:
        inf_mask |= np.isinf(df[col])

    before = len(df)
    n_dropped = int(inf_mask.sum())

    if n_dropped == 0:
        log.info("No infinite values found. Nothing dropped.")
        return df

    pct = (n_dropped / before) * 100
    log.info("Dropping %s rows with infinite values (%.4f%% of dataset)",
              f"{n_dropped:,}", pct)
    log_label_breakdown(df.loc[inf_mask], "  Label breakdown of dropped inf rows")

    bot_dropped = int((df.loc[inf_mask, LABEL_COL] == "Bot").sum())
    if bot_dropped > 0:
        bot_total = int((df[LABEL_COL] == "Bot").sum())
        log.warning("  Bot-class rows among dropped inf rows: %s (%.4f%% of Bot class)",
                     bot_dropped, (bot_dropped / bot_total) * 100)

    cleaned = df.loc[~inf_mask].reset_index(drop=True)
    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def drop_negative_duration(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: drop rows with negative Flow Duration (confirmed BENIGN-only)."""
    _step_header("Drop negative Flow Duration rows")
    if "Flow Duration" not in df.columns:
        log.warning("'Flow Duration' column not found — skipping this step")
        return df

    neg_mask = df["Flow Duration"] < 0
    before = len(df)
    n_dropped = int(neg_mask.sum())

    if n_dropped == 0:
        log.info("No negative Flow Duration rows found. Nothing dropped.")
        return df

    pct = (n_dropped / before) * 100
    log.info("Dropping %s rows with negative Flow Duration (%.4f%% of dataset)",
              f"{n_dropped:,}", pct)
    log_label_breakdown(df.loc[neg_mask], "  Label breakdown of dropped rows")

    non_benign = df.loc[neg_mask & (df[LABEL_COL] != "BENIGN")]
    if not non_benign.empty:
        log.warning("  UNEXPECTED: %s non-BENIGN rows among negative-duration rows "
                     "— this contradicts the earlier verification. Review before trusting output.",
                     len(non_benign))
    else:
        log.info("  Confirmed: all dropped rows are BENIGN, as expected.")

    cleaned = df.loc[~neg_mask].reset_index(drop=True)
    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def drop_duplicate_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: drop duplicate rows, keep first occurrence."""
    _step_header("Drop duplicate rows (keep first)")
    before = len(df)
    dup_mask = df.duplicated(keep="first")
    n_dropped = int(dup_mask.sum())

    if n_dropped == 0:
        log.info("No duplicate rows found. Nothing dropped.")
        return df

    pct = (n_dropped / before) * 100
    log.info("Dropping %s duplicate rows (%.4f%% of dataset)", f"{n_dropped:,}", pct)
    log_label_breakdown(df.loc[dup_mask], "  Label breakdown of dropped duplicates")

    bot_dropped = int((df.loc[dup_mask, LABEL_COL] == "Bot").sum())
    bot_total = int((df[LABEL_COL] == "Bot").sum())
    if bot_dropped > 0:
        log.warning("  Bot-class duplicates dropped: %s out of %s total Bot rows (%.4f%%)",
                     bot_dropped, bot_total, (bot_dropped / bot_total) * 100)
    else:
        log.info("  No Bot-class rows among dropped duplicates.")

    cleaned = df.drop_duplicates(keep="first").reset_index(drop=True)
    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def filter_tier1_scope(df: pd.DataFrame) -> pd.DataFrame:
    """Decision: keep only Tier-1 scope labels; drop everything else, unbucketed."""
    _step_header("Filter to Tier-1 scope labels")
    if LABEL_COL not in df.columns:
        log.warning("'Label' column not found — skipping this step")
        return df

    before = len(df)
    keep_mask = df[LABEL_COL].isin(TIER1_LABELS)
    n_dropped = int((~keep_mask).sum())

    if n_dropped > 0:
        pct = (n_dropped / before) * 100
        log.info("Dropping %s out-of-scope rows (%.4f%% of dataset)", f"{n_dropped:,}", pct)
        log_label_breakdown(df.loc[~keep_mask], "  Label breakdown of dropped (out-of-scope) rows")
    else:
        log.info("No out-of-scope rows found.")

    cleaned = df.loc[keep_mask].reset_index(drop=True)
    log.info("Tier-1 labels kept: %s", TIER1_LABELS)
    log.info("Rows remaining: %s", f"{len(cleaned):,}")
    return cleaned


def apply_log1p_transform(df: pd.DataFrame) -> pd.DataFrame:
    """NOT called from main() — kept here for reference/reuse only.

    Intentionally deferred to the Isolation Forest training script.
    Import this function from there (or copy its logic) and call it
    right before df.fit(), on the IF-specific training subset only —
    never on the shared cleaned CSV this script produces.
    """
    cleaned = df.copy()

    for col in LOG1P_COLUMNS:
        if col not in cleaned.columns:
            log.warning("Column '%s' not found — skipping", col)
            continue

        n_negative = int((cleaned[col] < 0).sum())
        if n_negative > 0:
            log.warning(
                "%-20s: %s unexpected negative values found before log1p "
                "(should be 0 — verified via check_negative_values.py). "
                "Clipping to 0 as a safety fallback — review this.",
                col, n_negative,
            )
            cleaned.loc[cleaned[col] < 0, col] = 0
        else:
            log.info("%-20s: no negative values — safe for log1p (as verified).", col)

        cleaned[col] = np.log1p(cleaned[col])

    log.info("log1p applied to: %s", LOG1P_COLUMNS)
    return cleaned


# --------------------------------------------------------------------------
# Before/after summary (for evaluator documentation)
# --------------------------------------------------------------------------

def write_summary(before_df: pd.DataFrame, after_df: pd.DataFrame, summary_path: Path) -> None:
    """Write a before/after row-count and class-distribution summary as Markdown."""
    _step_header("Writing before/after summary")

    lines = []
    lines.append("# Dataset Cleaning Summary — PS26145\n")
    lines.append(f"| Metric | Before | After |\n|---|---|---|")
    lines.append(f"| Total rows | {len(before_df):,} | {len(after_df):,} |")
    lines.append(f"| Total columns | {before_df.shape[1]} | {after_df.shape[1]} |")
    n_removed = len(before_df) - len(after_df)
    pct_removed = (n_removed / len(before_df)) * 100 if len(before_df) else 0
    lines.append(f"| Rows removed | — | {n_removed:,} ({pct_removed:.2f}%) |\n")

    lines.append("## Class distribution — BEFORE\n")
    lines.append("| Label | Count | % |\n|---|---|---|")
    before_counts = before_df[LABEL_COL].value_counts()
    for label, count in before_counts.items():
        pct = (count / len(before_df)) * 100
        lines.append(f"| {label} | {count:,} | {pct:.4f}% |")

    lines.append("\n## Class distribution — AFTER\n")
    lines.append("| Label | Count | % |\n|---|---|---|")
    after_counts = after_df[LABEL_COL].value_counts()
    for label, count in after_counts.items():
        pct = (count / len(after_df)) * 100
        lines.append(f"| {label} | {count:,} | {pct:.4f}% |")

    summary_text = "\n".join(lines) + "\n"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary_text, encoding="utf-8")
    log.info("Summary written to %s", summary_path)

    print("\n" + summary_text)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clean the CICIDS2017 12-feature dataset per Decisions #1-8."
    )
    parser.add_argument(
        "--input",
        default="data/processed/cicids2017_12_features.csv",
        help="Path to the raw dataset CSV.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/cicids2017_12_features_cleaned.csv",
        help="Path to write the cleaned dataset CSV.",
    )
    parser.add_argument(
        "--summary-output",
        default=None,
        help="Path to write the before/after Markdown summary. "
             "Defaults to <output_dir>/cleaning_summary.md",
    )
    args = parser.parse_args()

    df_raw = load_data(args.input)
    before_df = df_raw.copy()

    df = drop_fully_null_row(df_raw)
    df = impute_zero_division_nan(df)
    df = drop_infinite_rows(df)
    df = drop_negative_duration(df)
    df = drop_duplicate_rows(df)
    df = filter_tier1_scope(df)
    # log1p is intentionally NOT called here — deferred to Isolation
    # Forest training. This CSV is left at raw feature values.

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    log.info("Cleaned dataset written to %s (%s rows, %s columns)",
              output_path, f"{len(df):,}", df.shape[1])

    summary_path = Path(args.summary_output) if args.summary_output else output_path.parent / "cleaning_summary.md"
    write_summary(before_df, df, summary_path)


if __name__ == "__main__":
    main()