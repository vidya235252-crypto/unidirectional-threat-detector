"""
prepare_training_datasets.py
=============================
Second-layer domain cleaning + feature consolidation + dual-pipeline export.

Takes the already first-layer-cleaned, class-scoped dataset
(data/processed/FINAL_DATA_cleaned.csv — nulls/infinities/duplicates
already handled, already scoped to Normal Traffic/DDoS/Port Scanning/Bots)
and produces two model-ready CSVs:

    - cleaned_network_data_rf.csv       -> Random Forest (raw features)
    - cleaned_network_data_iforest.csv  -> Isolation Forest (log1p on
                                            heavy-tailed features only)

Pipeline (in order):
    1. Domain-specific cleaning: drop physically-impossible rows
       (negative duration/IAT/byte-rate — these are parser/capture
       artifacts, not real traffic, and would silently corrupt both
       distance-based (iForest) and split-based (RF) learning).
    2. Feature consolidation: drop the two features flagged by the
       profiling report (dataset_statistics.md) for multicollinearity
       and sparsity.
    3. Build two DataFrames from the same consolidated base: RF gets
       raw values (tree splits are scale/shape invariant, so raw is
       both trainable and human-auditable); iForest gets log1p on the
       heavy-tailed columns only (iForest isolates via random splits
       on magnitude, so uncompressed heavy tails let a handful of
       extreme-but-benign flows isolate as fast as real attacks).
    4. Export both to data/processed/.

'Attack Type' is retained in both outputs: RF needs it as the training
label, and iForest needs it too — not for training (it stays
unsupervised) but to evaluate anomaly-score performance afterward
(precision/recall against known attack rows). Drop the column yourself
downstream if your iForest training call requires a label-free frame.

Usage
-----
    python prepare_training_datasets.py

Reads   : data/processed/FINAL_DATA_cleaned.csv
Writes  : data/processed/cleaned_network_data_rf.csv
          data/processed/cleaned_network_data_iforest.csv

Dependencies: pandas, numpy
"""

from pathlib import Path
import sys
import pandas as pd
import numpy as np

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

INPUT_PATH = Path("data/processed/FINAL_DATA_cleaned.csv")
OUTPUT_DIR = Path("data/processed")

RF_OUTPUT_PATH = OUTPUT_DIR / "cleaned_network_data_rf.csv"
IFOREST_OUTPUT_PATH = OUTPUT_DIR / "cleaned_network_data_iforest.csv"

TARGET_COL = "Attack Type"

# Columns that must be non-negative to be physically valid traffic.
NON_NEGATIVE_COLS = ["Flow Duration", "Flow IAT Mean", "Flow IAT Max", "Flow Bytes/s"]

# Features dropped per the profiling report (Section 3a / 5a of
# dataset_statistics.md): Fwd Packet Length Std <-> Mean (r=0.90, also
# 64.3% sparse); Flow IAT Max <-> Flow IAT Std (r=0.897).
COLS_TO_DROP = ["Fwd Packet Length Std", "Flow IAT Max"]

# Heavy-tailed columns (high positive kurtosis in the profiling report)
# log1p-transformed for the iForest pipeline only. Note: since
# 'Flow IAT Max' is dropped in Step 2, it is intentionally absent here
# even though it appeared in the original high-kurtosis findings.
LOG_TRANSFORM_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Fwd Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
]


# --------------------------------------------------------------------------
# Step 0 — Load
# --------------------------------------------------------------------------

def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"[FATAL] Input file not found at '{path}'.")
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()  # strip accidental whitespace from headers
    print(f"[INFO] Loaded {len(df):,} rows x {df.shape[1]} columns from '{path}'.")
    return df


# --------------------------------------------------------------------------
# Step 1 — Domain-specific cleaning (physically impossible rows)
# --------------------------------------------------------------------------

def drop_invalid_rows(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)

    invalid_mask = pd.Series(False, index=df.index)
    for col in NON_NEGATIVE_COLS:
        if col not in df.columns:
            sys.exit(f"[FATAL] Expected column '{col}' not found — check header spelling/whitespace.")
        invalid_mask |= (df[col] < 0)

    dropped_per_col = {col: int((df[col] < 0).sum()) for col in NON_NEGATIVE_COLS}

    cleaned = df.loc[~invalid_mask].copy()
    after = len(cleaned)

    print(f"[INFO] Domain cleaning: dropped {before - after:,} logically invalid rows "
          f"(negative Flow Duration / Flow IAT Mean / Flow IAT Max / Flow Bytes/s).")
    print(f"[INFO] Breakdown by column (rows overlap where multiple were negative on the same row): "
          f"{dropped_per_col}")

    return cleaned


# --------------------------------------------------------------------------
# Step 2 — Feature consolidation (multicollinearity & sparsity)
# --------------------------------------------------------------------------

def consolidate_features(df: pd.DataFrame) -> pd.DataFrame:
    present_to_drop = [c for c in COLS_TO_DROP if c in df.columns]
    missing = set(COLS_TO_DROP) - set(present_to_drop)
    if missing:
        print(f"[WARN] Columns already absent, nothing to drop: {sorted(missing)}")

    consolidated = df.drop(columns=present_to_drop)

    remaining_features = [c for c in consolidated.columns if c != TARGET_COL]
    print(f"[INFO] Dropped for multicollinearity/sparsity: {present_to_drop}")
    print(f"[INFO] {len(remaining_features)} remaining active features:")
    for f in remaining_features:
        print(f"       - {f}")

    return consolidated


# --------------------------------------------------------------------------
# Step 3 — Dual-pipeline generation
# --------------------------------------------------------------------------

def build_rf_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """RF pipeline: raw, human-verifiable numeric values, untouched."""
    return df.copy()


def build_iforest_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """iForest pipeline: log1p on heavy-tailed columns only.

    log1p (not plain log) is used so that legitimate zero values
    (e.g. a flow with zero measured IAT std) map to log1p(0) = 0
    instead of raising on log(0) = -inf. Values are clipped at 0
    first as a defensive guard — Step 1 already removes negative
    Flow Duration/IAT/Bytes-per-sec, but Total Fwd Packets / Total
    Length of Fwd Packets / Fwd Packets/s / Flow IAT Std were not
    part of that negativity filter, so this guard prevents a NaN
    from a stray negative slipping through silently.
    """
    df_iforest = df.copy()

    cols_present = [c for c in LOG_TRANSFORM_COLS if c in df_iforest.columns]
    missing = set(LOG_TRANSFORM_COLS) - set(cols_present)
    if missing:
        print(f"[WARN] Log-transform columns not found (already dropped upstream?): {sorted(missing)}")

    for col in cols_present:
        clipped = df_iforest[col].clip(lower=0)
        df_iforest[col] = np.log1p(clipped)

    print(f"[INFO] Log1p-transformed for iForest pipeline: {cols_present}")
    return df_iforest


# --------------------------------------------------------------------------
# Step 4 — Export
# --------------------------------------------------------------------------

def export(df_rf: pd.DataFrame, df_iforest: pd.DataFrame) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df_rf.to_csv(RF_OUTPUT_PATH, index=False)
    df_iforest.to_csv(IFOREST_OUTPUT_PATH, index=False)

    print(f"\n[RESULT] RF pipeline      -> '{RF_OUTPUT_PATH}'      "
          f"| shape: {df_rf.shape[0]:,} rows x {df_rf.shape[1]} cols")
    print(f"[RESULT] iForest pipeline -> '{IFOREST_OUTPUT_PATH}' "
          f"| shape: {df_iforest.shape[0]:,} rows x {df_iforest.shape[1]} cols")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    df = load_data(INPUT_PATH)
    df = drop_invalid_rows(df)
    df = consolidate_features(df)

    df_rf = build_rf_dataframe(df)
    df_iforest = build_iforest_dataframe(df)

    export(df_rf, df_iforest)


if __name__ == "__main__":
    main()