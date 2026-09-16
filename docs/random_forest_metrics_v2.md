# Random Forest v2 — PS26145

## Changes vs. v1 (docs/random_forest_metrics.md)
1. **Added engineered feature `IAT_CV`** = Flow IAT Std / Flow IAT Mean (periodicity signal, same ratio the heuristic Bot rule used).
2. **class_weight changed** from `'balanced'` to explicit dict `{'BENIGN': 1, 'Bot': 15, 'PortScan': 1, 'DDoS': 1}`.

## Split
- 80% train / 20% test, stratified by Label, random_state=42
- Train rows: 1,741,552 | Test rows: 435,388

## Model / Run configuration
- RandomForestClassifier, n_estimators=300, class_weight={'BENIGN': 1, 'Bot': 15, 'PortScan': 1, 'DDoS': 1}, random_state=42
- Trained on raw (non-log1p) feature values
- Feature columns (12): Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, SYN Flag Count, Down/Up Ratio, Average Packet Size, IAT_CV
  (`IAT_CV` is the new engineered feature — not present in the v1 run)

## Before / After comparison (v1 → v2)
| Metric | v1 | v2 | Change |
|---|---|---|---|
| Overall accuracy | 0.9983 | 0.9982 | -0.0001 |
| BENIGN false-positive rate | 0.1587% | 0.1027% | -0.0560 pp |
| BENIGN — Precision | 0.9997 | 0.9990 | -0.0007 |
| BENIGN — Recall | 0.9984 | 0.9990 | +0.0006 |
| BENIGN — F1 | 0.9991 | 0.9990 | -0.0001 |
| Bot — Precision | 0.4574 | 0.5837 | +0.1263 |
| Bot — Recall | 0.7738 | 0.6093 | -0.1645 |
| Bot — F1 | 0.5750 | 0.5962 | +0.0212 |
| PortScan — Precision | 0.9876 | 0.9880 | +0.0004 |
| PortScan — Recall | 0.9997 | 0.9889 | -0.0108 |
| PortScan — F1 | 0.9936 | 0.9885 | -0.0051 |
| DDoS — Precision | 0.9986 | 0.9994 | +0.0008 |
| DDoS — Recall | 0.9996 | 0.9993 | -0.0003 |
| DDoS — F1 | 0.9991 | 0.9993 | +0.0002 |

> Positive Change = improvement for Precision/Recall/F1/Accuracy. Positive Change on BENIGN FPR = MORE false positives (worse).

## Test-set metrics (v2, full detail)
| Label | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.9990 | 0.9990 | 0.9990 | 391258 |
| Bot | 0.5837 | 0.6093 | 0.5962 | 389 |
| PortScan | 0.9880 | 0.9889 | 0.9885 | 18139 |
| DDoS | 0.9994 | 0.9993 | 0.9993 | 25602 |

**Overall accuracy:** 0.9982

**BENIGN false-positive rate:** 0.1027%

## Confusion matrix (rows = actual, columns = predicted)
| | BENIGN | Bot | PortScan | DDoS |
|---|---|---|---|---|
| BENIGN | 390856 | 169 | 217 | 16 |
| Bot | 152 | 237 | 0 | 0 |
| PortScan | 202 | 0 | 17937 | 0 |
| DDoS | 19 | 0 | 0 | 25583 |

## Top global feature importances (Gini)
| Feature | Importance |
|---|---|
| Average Packet Size | 0.2749 |
| Destination Port | 0.1967 |
| Total Fwd Packets | 0.0961 |
| Total Backward Packets | 0.0851 |
| Flow Bytes/s | 0.0844 |
| IAT_CV | 0.0802 |
| Flow Duration | 0.0493 |
| Flow IAT Std | 0.0411 |
| Flow Packets/s | 0.0340 |
| Down/Up Ratio | 0.0292 |
| Flow IAT Mean | 0.0287 |
| SYN Flag Count | 0.0003 |

> Note: these are GLOBAL importances, not the per-flow `top_features` required by the frozen Inference Response contract — see the docstring in `get_top_features()`.