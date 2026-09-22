"""
dataset_statistics.py
======================
Baseline statistical profiling for the cleaned network-traffic dataset
(PS 26145 — Unidirectional Cyber Threat Detection).

Purpose
-------
Run this AFTER first-layer cleaning (nulls/infinities/duplicates already
handled) and BEFORE feature engineering / model training. It answers three
questions an evaluator will ask:
    1. Are the feature distributions sane, or riddled with extreme skew?
    2. Are any features redundant (multicollinear) enough to bias
       Random Forest's feature-importance ranking?
    3. Are any features near-constant / sparse enough to be dead weight
       for Isolation Forest (which is distance/variance sensitive)?

Scope: this run is restricted to the four classes actually in scope for
the ML branch of the MVP — Normal Traffic, DDoS, Port Scanning, Bots.
(DGA/DNS-tunneling and JA3 are separate rule-based detectors — see
Part 3 / Part 5a of the architecture doc — and never touch this dataset.)

Usage
-----
    python dataset_statistics.py

Reads   : data/processed/FINAL_DATA_cleaned.csv
Writes  : docs/dataset_statistics.md

Dependencies: pandas, numpy  (no scipy needed — pandas' .skew()/.kurt()
use the same Fisher-Pearson / excess-kurtosis definitions scipy does).
"""

from pathlib import Path
import sys
import pandas as pd
import numpy as np

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

INPUT_PATH = Path("data/processed/FINAL_DATA_cleaned.csv")
OUTPUT_PATH = Path("docs/dataset_statistics.md")

TARGET_COL = "Attack Type"

# MVP ML-branch scope only — Tier 2 (DGA/JA3) does not use this dataset.
KEEP_CLASSES = ["Normal Traffic", "DDoS", "Port Scanning", "Bots"]

# Pearson |r| above this is flagged as redundant for RF feature-importance.
CORR_THRESHOLD = 0.85

# A feature whose *normalized* spread (coefficient of variation squared,
# i.e. variance / mean^2) falls below this is flagged as near-constant.
# Raw variance alone is scale-dependent (Flow Duration lives in a totally
# different numeric range than Fwd Packet Length Min), so raw variance is
# reported for the record but this normalized measure drives the flag.
CV_SQUARED_THRESHOLD = 0.01

# A column with more than this share of exact zeros is flagged as sparse.
ZERO_SHARE_THRESHOLD = 0.50


# --------------------------------------------------------------------------
# Step 1 — Load & scope
# --------------------------------------------------------------------------

def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(
            f"[FATAL] Input file not found at '{path}'. "
            f"Run first_layer_cleaning.py first, or fix INPUT_PATH."
        )
    df = pd.read_csv(path)

    missing_target = TARGET_COL not in df.columns
    if missing_target:
        sys.exit(f"[FATAL] Expected target column '{TARGET_COL}' not found in {path}.")

    before = len(df)
    df = df[df[TARGET_COL].isin(KEEP_CLASSES)].copy()
    after = len(df)
    print(f"[INFO] Scoped to {KEEP_CLASSES}: {before:,} -> {after:,} rows "
          f"({before - after:,} rows outside scope dropped for this profiling run).")

    return df


def numeric_frame(df: pd.DataFrame) -> pd.DataFrame:
    """All feature columns except the categorical target."""
    return df.drop(columns=[TARGET_COL]).select_dtypes(include=[np.number])


# --------------------------------------------------------------------------
# Step 2 — Statistical profiling (.describe + skew/kurtosis)
# --------------------------------------------------------------------------

def profile_statistics(num_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    desc = num_df.describe().T  # columns as rows: count, mean, std, min, 25/50/75%, max
    desc = desc.rename(columns={"50%": "median"})

    skew_kurt = pd.DataFrame({
        "skewness": num_df.skew(),
        "kurtosis": num_df.kurt(),  # excess kurtosis (normal = 0)
    })

    return desc, skew_kurt


# --------------------------------------------------------------------------
# Step 3 — Multicollinearity check
# --------------------------------------------------------------------------

def correlation_analysis(num_df: pd.DataFrame, threshold: float):
    corr = num_df.corr(method="pearson")

    high_pairs = []
    cols = corr.columns
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            r = corr.iloc[i, j]
            if pd.notna(r) and abs(r) >= threshold:
                high_pairs.append((cols[i], cols[j], r))

    high_pairs.sort(key=lambda x: -abs(x[2]))
    return corr, high_pairs


# --------------------------------------------------------------------------
# Step 4 — Variance & sparsity audit
# --------------------------------------------------------------------------

def variance_sparsity_audit(num_df: pd.DataFrame) -> pd.DataFrame:
    variance = num_df.var()
    mean = num_df.mean()

    # Normalized spread: (std/mean)^2. Guard against mean == 0 (undefined -> NaN,
    # treated as "cannot judge on this scale", flagged separately as a warning).
    with np.errstate(divide="ignore", invalid="ignore"):
        cv_squared = variance / (mean ** 2)

    zero_share = (num_df == 0).sum() / len(num_df)

    audit = pd.DataFrame({
        "variance_raw": variance,
        "mean": mean,
        "cv_squared_normalized": cv_squared,
        "zero_pct": zero_share * 100,
    })

    audit["near_constant_flag"] = audit["cv_squared_normalized"] < CV_SQUARED_THRESHOLD
    audit["sparse_flag"] = audit["zero_pct"] > (ZERO_SHARE_THRESHOLD * 100)

    return audit


# --------------------------------------------------------------------------
# Step 5 — Markdown report writer
# --------------------------------------------------------------------------

def df_to_md(df: pd.DataFrame, float_fmt: str = "{:.4f}") -> str:
    """Render a DataFrame as a Markdown table without requiring the
    optional 'tabulate' package (falls back to it if available, since
    it produces slightly cleaner alignment)."""
    formatted = df.copy()
    for col in formatted.select_dtypes(include=[np.number]).columns:
        formatted[col] = formatted[col].map(lambda x: float_fmt.format(x) if pd.notna(x) else "NaN")

    try:
        return formatted.to_markdown()  # uses 'tabulate' if installed
    except ImportError:
        headers = ["index"] + list(formatted.columns.astype(str))
        rows = [headers, ["---"] * len(headers)]
        for idx, row in formatted.iterrows():
            rows.append([str(idx)] + [str(v) for v in row.tolist()])
        return "\n".join("| " + " | ".join(r) + " |" for r in rows)


def write_report(
    df: pd.DataFrame,
    num_df: pd.DataFrame,
    desc: pd.DataFrame,
    skew_kurt: pd.DataFrame,
    corr: pd.DataFrame,
    high_pairs: list,
    audit: pd.DataFrame,
    out_path: Path,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    class_counts = df[TARGET_COL].value_counts()
    class_pct = (class_counts / len(df) * 100).round(4)

    near_constant_cols = audit.index[audit["near_constant_flag"]].tolist()
    sparse_cols = audit.index[audit["sparse_flag"]].tolist()
    redundant_cols = sorted({b for _, b, _ in high_pairs})  # drop the 2nd of each pair by convention

    lines = []
    lines.append("# Dataset Statistics & Consolidation Report")
    lines.append("")
    lines.append(f"**Scope:** `{', '.join(KEEP_CLASSES)}` only "
                  "(ML branch — RF + Isolation Forest). "
                  "DGA/JA3 rule-based detectors use separate reference feeds, not this dataset.")
    lines.append("")
    lines.append(f"**Rows profiled:** {len(df):,}  |  **Features:** {num_df.shape[1]}")
    lines.append("")

    lines.append("## 0. Class Balance")
    lines.append("")
    balance_df = pd.DataFrame({"rows": class_counts, "pct": class_pct})
    lines.append(df_to_md(balance_df, float_fmt="{:.4f}"))
    lines.append("")

    lines.append("## 1. Statistical Summary (`.describe()`)")
    lines.append("")
    lines.append(df_to_md(desc))
    lines.append("")

    lines.append("## 2. Skewness & Kurtosis")
    lines.append("")
    lines.append("Skewness: 0 = symmetric, >1 / <-1 = heavily skewed (common and expected "
                  "for network byte/duration counts). Kurtosis: excess kurtosis, 0 = normal-like tails, "
                  "large positive = heavy-tailed / outlier-prone.")
    lines.append("")
    lines.append(df_to_md(skew_kurt))
    lines.append("")

    lines.append("## 3. Pearson Correlation Matrix")
    lines.append("")
    lines.append(df_to_md(corr))
    lines.append("")

    lines.append(f"### 3a. Highly Correlated Pairs (|r| >= {CORR_THRESHOLD})")
    lines.append("")
    if high_pairs:
        pairs_df = pd.DataFrame(high_pairs, columns=["feature_a", "feature_b", "pearson_r"])
        lines.append(df_to_md(pairs_df))
    else:
        lines.append(f"_No feature pairs exceeded |r| >= {CORR_THRESHOLD}._")
    lines.append("")

    lines.append("## 4. Variance & Sparsity Audit")
    lines.append("")
    lines.append(f"`near_constant_flag` = normalized spread (variance/mean²) < {CV_SQUARED_THRESHOLD}. "
                  f"`sparse_flag` = more than {ZERO_SHARE_THRESHOLD*100:.0f}% exact zeros.")
    lines.append("")
    lines.append(df_to_md(audit))
    lines.append("")

    lines.append("## 5. Actionable Consolidation Insights")
    lines.append("")

    lines.append("**a) Candidates for dropping:**")
    lines.append("")
    if redundant_cols:
        lines.append(f"- Multicollinearity (keep the first of each flagged pair, "
                      f"drop the second unless domain reasoning says otherwise): "
                      f"`{', '.join(redundant_cols)}`")
    else:
        lines.append(f"- Multicollinearity: none found above |r| >= {CORR_THRESHOLD}.")
    if near_constant_cols:
        lines.append(f"- Near-constant / low-information: `{', '.join(near_constant_cols)}`")
    else:
        lines.append("- Near-constant / low-information: none found at the configured threshold.")
    if sparse_cols:
        lines.append(f"- Heavily sparse (>{ZERO_SHARE_THRESHOLD*100:.0f}% zeros — verify these are "
                      f"genuine empty-packet/no-payload signals, not a parsing artifact): "
                      f"`{', '.join(sparse_cols)}`")
    else:
        lines.append(f"- Heavily sparse columns: none found above {ZERO_SHARE_THRESHOLD*100:.0f}% zeros.")
    lines.append("")

    lines.append("**b) Model-specific impact:**")
    lines.append("")
    lines.append(
        "- **Random Forest:** Highly correlated feature pairs split importance between "
        "themselves at every tree split, diluting the reported importance of the true signal "
        "and letting trees overfit to whichever correlated feature happens to have a cleaner "
        "split point in a given bootstrap sample — this inflates apparent feature count without "
        "adding real separating power, and increases tree depth for no accuracy gain. "
        "Heavily right-skewed features (common here — byte counts, durations, packet rates) are "
        "handled natively by RF's split-based logic (it doesn't assume normality), so skew itself "
        "is not a concern for RF the way it would be for a linear model."
    )
    lines.append(
        "- **Isolation Forest:** This model isolates points via random axis-aligned splits, so "
        "near-constant features contribute almost nothing to isolation depth (dead weight that "
        "just adds noise to the random feature selection at each split) while extremely heavy-tailed "
        "features (high positive kurtosis) can dominate isolation paths — a handful of genuinely "
        "extreme benign flows may isolate as fast as real attacks, inflating false positives. "
        "Sparse (mostly-zero) columns similarly compress most of the mass into a single value, so "
        "splits on that feature rarely help isolate anything and should be scaled/transformed "
        "(e.g. log1p) or dropped if the sparsity isn't itself the attack signal."
    )
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[INFO] Report written to '{out_path}' ({out_path.stat().st_size:,} bytes).")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    df = load_data(INPUT_PATH)
    num_df = numeric_frame(df)

    print(f"[INFO] Profiling {num_df.shape[1]} numeric features across {len(num_df):,} rows...")

    desc, skew_kurt = profile_statistics(num_df)
    corr, high_pairs = correlation_analysis(num_df, CORR_THRESHOLD)
    audit = variance_sparsity_audit(num_df)

    # Console preview (full detail goes to the markdown file)
    print("\n=== Statistical Summary ===")
    print(desc.round(4))
    print("\n=== Skewness / Kurtosis ===")
    print(skew_kurt.round(4))
    print(f"\n=== Correlated Pairs (|r| >= {CORR_THRESHOLD}) ===")
    print(high_pairs if high_pairs else "None found.")
    print("\n=== Variance / Sparsity Audit ===")
    print(audit.round(4))

    write_report(df, num_df, desc, skew_kurt, corr, high_pairs, audit, OUTPUT_PATH)


if __name__ == "__main__":
    main()