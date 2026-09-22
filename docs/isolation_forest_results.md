# Isolation Forest — Baseline Anomaly Score Results

Trained on 1,392,049 Normal Traffic rows from the train split of `data\processed\cleaned_network_data_iforest.csv`.

Params: `n_estimators=200`, `contamination=0.05`, `random_state=42`, `n_jobs=-1`.

Lower `decision_function` / `score_samples` = more anomalous. `pct_flagged_anomaly` is the share of rows in that class the model's own contamination-derived threshold flagged as -1.

## Validation set

| Attack Type    |   count |   mean_decision_function |   median_decision_function |   mean_score_samples |   median_score_samples |   pct_flagged_anomaly |
|:---------------|--------:|-------------------------:|---------------------------:|---------------------:|-----------------------:|----------------------:|
| Port Scanning  |   13604 |                   0.0565 |                     0.0618 |              -0.5027 |                -0.4973 |                  1.27 |
| Bots           |     291 |                   0.0685 |                     0.0776 |              -0.4907 |                -0.4816 |                  1.72 |
| DDoS           |   19201 |                   0.0877 |                     0.0844 |              -0.4715 |                -0.4748 |                  0.01 |
| Normal Traffic |  298297 |                   0.1    |                     0.1083 |              -0.4592 |                -0.4509 |                  5.01 |

## Test set

| Attack Type    |   count |   mean_decision_function |   median_decision_function |   mean_score_samples |   median_score_samples |   pct_flagged_anomaly |
|:---------------|--------:|-------------------------:|---------------------------:|---------------------:|-----------------------:|----------------------:|
| Port Scanning  |   13604 |                   0.0568 |                     0.062  |              -0.5024 |                -0.4972 |                  0.91 |
| Bots           |     292 |                   0.0664 |                     0.0777 |              -0.4928 |                -0.4815 |                  3.42 |
| DDoS           |   19201 |                   0.0873 |                     0.0834 |              -0.4719 |                -0.4757 |                  0.02 |
| Normal Traffic |  298297 |                   0.1    |                     0.1079 |              -0.4592 |                -0.4513 |                  4.99 |
