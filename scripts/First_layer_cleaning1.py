"""
first_layer_cleaning.py

PS26145 - unidirectional-threat-detector
First-Layer Basic Cleaning of the 12-feature CICIDS2017 dataset.

Steps (exact order)
-------------------
1. Standardise column names (strip whitespace)
2. Handle infinite values (+inf / -inf)
3. Handle NaN / null values (drop rows, report count)
4. Drop exact duplicate rows (keep first, report count)
5. Print cleaned-data summary (shape + no-NaN / no-inf confirmation)
6. Report attack-type distribution, keep only BENIGN / PortScan / DDoS / Bot,
   and write before/after row counts to docs/cleaning_summary.md

Location : unidirectional-threat-detector/scripts/first_layer_cleaning.py
Input    : data/raw/FINAL_DATA.csv
Outputs  : data/processed/FINAL_DATA_cleaned.csv
           docs/cleaning_summary.md

Run from anywhere:  python scripts/first_layer_cleaning.py
"""

import re
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ── CONFIG ───────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent          # project root
INPUT_PATH = ROOT / "data" / "raw" / "FINAL_DATA.csv"
OUTPUT_PATH = ROOT / "data" / "processed" / "FINAL_DATA_cleaned.csv"
SUMMARY_PATH = ROOT / "docs" / "cleaning_summary.md"

LABEL_COL = "Attack Type"

FINAL_HACKATHON_VECTOR = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Flow Bytes/s", "Fwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Fwd Packet Length Min",
    "Attack Type",   # target column (used only for step 6)
]

# Step 2 behaviour. "rows" (default) = drop only rows containing inf, keeping all 12
# features intact; "columns" = drop every column containing inf (literal spec).
INF_MODE = "rows"

# Step 6 scope: attack types to KEEP, spelled as they appear in the dataset.
# (Matching ignores case, spaces, '_' and '-'; everything else is dropped.)
KEEP_LABELS = ["Normal Traffic", "Port Scanning", "DDoS", "Bots"]


# ── HELPERS ──────────────────────────────────────────────────────────────────
def label_key(value) -> str:
    """Normalise a label so 'Port Scan', 'PORTSCAN', 'port_scan' all match."""
    return re.sub(r"[\s_\-]", "", str(value)).lower()


KEEP_MAP = {label_key(name): name for name in KEEP_LABELS}   # key -> display name


def label_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Return count and percentage per attack type, largest first."""
    counts = df[LABEL_COL].value_counts()
    return pd.DataFrame({
        "Attack Type": counts.index,
        "Rows": counts.values,
        "Percentage": (counts.values / len(df) * 100).round(4),
    })


def md_table(df: pd.DataFrame) -> str:
    """Render a DataFrame as a Markdown table (no extra dependencies)."""
    lines = ["| " + " | ".join(df.columns) + " |",
             "|" + "|".join(["---"] * len(df.columns)) + "|"]
    for row in df.itertuples(index=False):
        cells = [f"{v:,}" if isinstance(v, (int, np.integer)) else str(v) for v in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def banner(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


# ── MAIN PIPELINE ────────────────────────────────────────────────────────────
def main() -> None:
    step_log = []  # (step, rows_before, rows_after, cols_after)

    df = pd.read_csv(INPUT_PATH, low_memory=False)
    raw_rows, raw_cols = df.shape
    print(f"Loaded {INPUT_PATH.name}: {raw_rows:,} rows x {raw_cols} columns")

    # 1. Column name standardisation ─────────────────────────────────────────
    banner("STEP 1 - Column name standardisation")
    df.columns = df.columns.str.strip()
    missing = [c for c in FINAL_HACKATHON_VECTOR if c not in df.columns]
    if missing:
        raise KeyError(f"Expected columns not found after stripping: {missing}")
    extras = [c for c in df.columns if c not in FINAL_HACKATHON_VECTOR]
    df = df[FINAL_HACKATHON_VECTOR]      # exact order, nothing extra
    print("Column names stripped. Dataset restricted to the 12-feature vector + Attack Type.")
    if extras:
        print(f"Ignored {len(extras)} extra column(s) not in the vector: {extras}")

    # 2. Infinite values ─────────────────────────────────────────────────────
    banner(f"STEP 2 - Infinite values (mode: {INF_MODE})")
    numeric = df.select_dtypes(include=[np.number])
    inf_mask = np.isinf(numeric)
    inf_per_col = inf_mask.sum()
    inf_per_col = inf_per_col[inf_per_col > 0]
    before = len(df)
    if inf_per_col.empty:
        print("No infinite values found.")
    else:
        print("Infinite values per column:")
        print(inf_per_col.to_string())
        if INF_MODE == "columns":
            df = df.drop(columns=inf_per_col.index.tolist())
            lost = [c for c in inf_per_col.index if c in FINAL_HACKATHON_VECTOR and c != LABEL_COL]
            print(f"Dropped columns: {inf_per_col.index.tolist()}")
            if lost:
                print(f"WARNING: {len(lost)} model feature(s) removed - the vector "
                      f"is no longer the frozen 12: {lost}")
        else:
            df = df.loc[~inf_mask.any(axis=1)]
            print(f"Dropped {before - len(df):,} rows containing inf/-inf.")
    step_log.append(("2. Infinite values", before, len(df), df.shape[1]))

    # 3. NaN / null values ───────────────────────────────────────────────────
    banner("STEP 3 - Missing (NaN/null) values")
    before = len(df)
    nan_per_col = df.isna().sum()
    nan_per_col = nan_per_col[nan_per_col > 0]
    print("NaN per column:\n" + nan_per_col.to_string() if not nan_per_col.empty
          else "No NaN values found.")
    df = df.dropna()
    nan_removed = before - len(df)
    print(f"Rows removed (NaN): {nan_removed:,}")
    step_log.append(("3. NaN rows", before, len(df), df.shape[1]))

    # 4. Duplicates ──────────────────────────────────────────────────────────
    banner("STEP 4 - Duplicate rows")
    before = len(df)
    df = df.drop_duplicates(keep="first")
    dup_removed = before - len(df)
    print(f"Duplicate rows removed: {dup_removed:,}")
    step_log.append(("4. Duplicates", before, len(df), df.shape[1]))

    # 5. Summary ─────────────────────────────────────────────────────────────
    banner("STEP 5 - Cleaned data summary")
    numeric = df.select_dtypes(include=[np.number])
    nulls_left = int(df.isna().sum().sum())
    infs_left = int(np.isinf(numeric).sum().sum())
    print(f"Shape after basic cleaning: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(f"Remaining nulls: {nulls_left} | Remaining infinities: {infs_left}")
    assert nulls_left == 0 and infs_left == 0, "Cleaning failed: NaN/inf remain"
    print("CONFIRMED: no NaN and no infinite values remain.")
    rows_after_basic = len(df)

    # 6. Attack-type distribution + scope filter ─────────────────────────────
    banner("STEP 6 - Attack-type distribution and scope filter")
    dist_before = label_distribution(df)
    print("BEFORE filtering:\n" + dist_before.to_string(index=False))

    keys = df[LABEL_COL].map(label_key)
    in_scope = keys.isin(KEEP_MAP)
    df = df.loc[in_scope].copy()
    df[LABEL_COL] = keys[in_scope].map(KEEP_MAP)         # canonical names
    step_log.append(("6. Scope filter", rows_after_basic, len(df), df.shape[1]))

    dist_after = label_distribution(df)
    print(f"\nAFTER filtering (kept {sorted(KEEP_LABELS)}):\n"
          + dist_after.to_string(index=False))
    print(f"\nRows before filter: {rows_after_basic:,} | after: {len(df):,} "
          f"| removed: {rows_after_basic - len(df):,}")
    print(f"FINAL SHAPE: {df.shape[0]:,} rows x {df.shape[1]} columns")

    # Save cleaned data ──────────────────────────────────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved cleaned dataset -> {OUTPUT_PATH}")

    # Write docs/cleaning_summary.md ─────────────────────────────────────────
    flow = pd.DataFrame(
        [("0. Raw file", raw_rows, raw_rows, raw_cols)] + step_log,
        columns=["Step", "Rows Before", "Rows After", "Columns After"],
    )
    flow["Rows Removed"] = flow["Rows Before"] - flow["Rows After"]

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(
        f"# First-Layer Cleaning Summary\n\n"
        f"_Generated {datetime.now():%Y-%m-%d %H:%M} by `scripts/first_layer_cleaning.py`_\n\n"
        f"- **Input:** `data/raw/{INPUT_PATH.name}`\n"
        f"- **Output:** `data/processed/{OUTPUT_PATH.name}`\n"
        f"- **Infinite-value handling mode:** `{INF_MODE}`\n\n"
        f"## Row counts per step\n\n{md_table(flow)}\n\n"
        f"- Rows removed for NaN: **{nan_removed:,}**\n"
        f"- Duplicate rows removed: **{dup_removed:,}**\n"
        f"- Remaining nulls / infinities: **{nulls_left} / {infs_left}**\n\n"
        f"## Attack-type distribution BEFORE filtering "
        f"({rows_after_basic:,} rows)\n\n{md_table(dist_before)}\n\n"
        f"## Attack-type distribution AFTER filtering ({len(df):,} rows)\n\n"
        f"Kept: {', '.join(sorted(KEEP_LABELS))}\n\n{md_table(dist_after)}\n\n"
        f"## Row count before vs after scope filter\n\n"
        f"| Before | After | Removed |\n|---|---|---|\n"
        f"| {rows_after_basic:,} | {len(df):,} | {rows_after_basic - len(df):,} |\n\n"
        f"**Final shape:** {df.shape[0]:,} rows x {df.shape[1]} columns\n",
        encoding="utf-8",
    )
    print(f"Saved summary -> {SUMMARY_PATH}")


if __name__ == "__main__":
    main()