# Random Forest — PS26145

## Split
- 80% train / 20% test, stratified by Label, random_state=42
- Train rows: 1,741,552 | Test rows: 435,388

## Model
- RandomForestClassifier, n_estimators=300, class_weight='balanced', random_state=42
- Trained on raw (non-log1p) feature values

## Test-set metrics
| Label | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.9997 | 0.9984 | 0.9991 | 391258 |
| Bot | 0.4574 | 0.7738 | 0.5750 | 389 |
| PortScan | 0.9876 | 0.9997 | 0.9936 | 18139 |
| DDoS | 0.9986 | 0.9996 | 0.9991 | 25602 |

**Overall accuracy:** 0.9983

**BENIGN false-positive rate:** 0.1587%

## Confusion matrix (rows = actual, columns = predicted)
| | BENIGN | Bot | PortScan | DDoS |
|---|---|---|---|---|
| BENIGN | 390637 | 357 | 227 | 37 |
| Bot | 88 | 301 | 0 | 0 |
| PortScan | 6 | 0 | 18133 | 0 |
| DDoS | 11 | 0 | 0 | 25591 |

## Top global feature importances (Gini)
| Feature | Importance |
|---|---|
| Destination Port | 0.2609 |
| Average Packet Size | 0.2567 |
| Total Fwd Packets | 0.1029 |
| Total Backward Packets | 0.0910 |
| Flow Duration | 0.0751 |
| Flow Bytes/s | 0.0713 |
| Flow IAT Std | 0.0504 |
| Flow Packets/s | 0.0436 |
| Flow IAT Mean | 0.0335 |
| Down/Up Ratio | 0.0122 |
| SYN Flag Count | 0.0024 |

> Note: these are GLOBAL importances, not the per-flow `top_features` required by the frozen Inference Response contract — see the docstring in `get_top_features()`.