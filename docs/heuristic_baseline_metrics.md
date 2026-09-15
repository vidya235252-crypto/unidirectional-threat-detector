# Heuristic Baseline — PS26145

## Split
- 80% train / 20% test, stratified by Label, random_state=42

## Thresholds (derived from TRAIN split, BENIGN rows only)
| Threshold | Value |
|---|---|
| P95_Packets_Per_Sec | 285,714.2857 |
| P5_Duration | 9.0000 |
| P25_Packet_Size | 10.3333 |
| High_Threshold_Duration | 115,453,376.7000 |

## Test-set metrics
| Label | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.8947 | 0.9585 | 0.9255 | 391,258 |
| Bot | 0.0000 | 0.0000 | 0.0000 | 389 |
| PortScan | 0.0000 | 0.0000 | 0.0000 | 18,139 |
| DDoS | 0.0000 | 0.0000 | 0.0000 | 25,602 |

**Overall accuracy:** 0.8614

**BENIGN false-positive rate:** 4.1451%

## Confusion matrix (rows = actual, columns = predicted)
| | BENIGN | Bot | PortScan | DDoS |
|---|---|---|---|---|
| BENIGN | 375,040 | 0 | 8,339 | 7,879 |
| Bot | 389 | 0 | 0 | 0 |
| PortScan | 18,139 | 0 | 0 | 0 |
| DDoS | 25,602 | 0 | 0 | 0 |
