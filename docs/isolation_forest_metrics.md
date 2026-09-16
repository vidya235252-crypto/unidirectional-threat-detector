# Isolation Forest — PS26145

## Training setup
- Model version: `if_v1`
- Fit rows (BENIGN, TRAIN split only): 1,252,028
- Calibration rows (held-out BENIGN, TRAIN split): 313,007
- n_estimators: 200
- contamination: 0.01
- Features (11): Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, SYN Flag Count, Average Packet Size, Down/Up Ratio
- log1p columns (pre-applied upstream in the input file): Flow Bytes/s, Flow Packets/s, Total Fwd Packets, Total Backward Packets, Flow IAT Mean, Flow IAT Std, Average Packet Size

## Threshold calibration
- Percentile used: 99.0
- Resulting threshold on anomaly_score: 0.62619
- Calibrated on held-out BENIGN TRAIN rows only (never TEST, never attack rows)

## TEST-set results (labels used for reporting only, not tuning)

| Label | Support | Mean anomaly_score | Median anomaly_score | % flagged anomalous |
|---|---|---|---|---|
| BENIGN | 391,258 | 0.45510 | 0.44523 | 0.97% |
| Bot | 389 | 0.46410 | 0.45611 | 0.51% |
| DDoS | 25,602 | 0.48914 | 0.48765 | 0.01% |
| PortScan | 18,139 | 0.46135 | 0.45713 | 0.00% |

> Note: BENIGN's '% flagged anomalous' is IF's false-positive rate.
> Non-BENIGN rows' '% flagged anomalous' is how often IF's independent signal agrees a flow looks abnormal — NOT a classification recall, since IF never saw class labels.
> anomaly_score is a corroborating signal only — it must never be presented downstream as a named classified threat.