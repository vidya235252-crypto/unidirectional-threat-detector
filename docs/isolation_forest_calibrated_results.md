# Isolation Forest — Calibrated Threshold Results

Trained on 1,392,049 Normal Traffic rows. `n_estimators=200`, `contamination=auto`, `random_state=42`.

Empirical threshold calibrated on the Validation set to reach ≥90% Bots recall at minimum Normal Traffic FPR: **`score_samples <= -0.4470`** = flagged anomalous.

Validation at this threshold: Bots recall = 0.9278, Normal Traffic FPR = 0.5223.

## Test set — percent flagged per class at calibrated threshold

| Attack Type    |   count |   pct_flagged |
|:---------------|--------:|--------------:|
| Bots           |     292 |         92.81 |
| DDoS           |   19201 |         86.16 |
| Normal Traffic |  298297 |         52.45 |
| Port Scanning  |   13604 |         99.97 |

Note: this model's output for downstream use is the continuous `score_samples` value, not a hard -1/1 label. The Alert Engine fusion step owns the final Bot-alert decision.
