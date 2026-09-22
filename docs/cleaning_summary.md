# First-Layer Cleaning Summary

_Generated 2026-09-21 20:57 by `scripts/first_layer_cleaning.py`_

- **Input:** `data/raw/FINAL_DATA.csv`
- **Output:** `data/processed/FINAL_DATA_cleaned.csv`
- **Infinite-value handling mode:** `rows`

## Row counts per step

| Step | Rows Before | Rows After | Columns After | Rows Removed |
|---|---|---|---|---|
| 0. Raw file | 2,520,751 | 2,520,751 | 13 | 0 |
| 2. Infinite values | 2,520,751 | 2,520,751 | 13 | 0 |
| 3. NaN rows | 2,520,751 | 2,520,751 | 13 | 0 |
| 4. Duplicates | 2,520,751 | 2,413,212 | 13 | 107,539 |
| 6. Scope filter | 2,413,212 | 2,209,336 | 13 | 203,876 |

- Rows removed for NaN: **0**
- Duplicate rows removed: **107,539**
- Remaining nulls / infinities: **0 / 0**

## Attack-type distribution BEFORE filtering (2,413,212 rows)

| Attack Type | Rows | Percentage |
|---|---|---|
| Normal Traffic | 1,988,691 | 82.4085 |
| DoS | 192,701 | 7.9852 |
| DDoS | 128,007 | 5.3044 |
| Port Scanning | 90,694 | 3.7582 |
| Brute Force | 9,084 | 0.3764 |
| Web Attacks | 2,091 | 0.0866 |
| Bots | 1,944 | 0.0806 |

## Attack-type distribution AFTER filtering (2,209,336 rows)

Kept: Bots, DDoS, Normal Traffic, Port Scanning

| Attack Type | Rows | Percentage |
|---|---|---|
| Normal Traffic | 1,988,691 | 90.0131 |
| DDoS | 128,007 | 5.7939 |
| Port Scanning | 90,694 | 4.105 |
| Bots | 1,944 | 0.088 |

## Row count before vs after scope filter

| Before | After | Removed |
|---|---|---|
| 2,413,212 | 2,209,336 | 203,876 |

**Final shape:** 2,209,336 rows x 13 columns
