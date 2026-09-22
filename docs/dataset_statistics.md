# Dataset Statistics & Consolidation Report

**Scope:** `Normal Traffic, DDoS, Port Scanning, Bots` only (ML branch — RF + Isolation Forest). DGA/JA3 rule-based detectors use separate reference feeds, not this dataset.

**Rows profiled:** 2,209,336  |  **Features:** 12

## 0. Class Balance

| index | rows | pct |
| --- | --- | --- |
| Normal Traffic | 1988691.0000 | 90.0131 |
| DDoS | 128007.0000 | 5.7939 |
| Port Scanning | 90694.0000 | 4.1050 |
| Bots | 1944.0000 | 0.0880 |

## 1. Statistical Summary (`.describe()`)

| index | count | mean | std | min | 25% | median | 75% | max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Destination Port | 2209336.0000 | 9696.9610 | 19848.5307 | 0.0000 | 53.0000 | 80.0000 | 443.0000 | 65535.0000 |
| Flow Duration | 2209336.0000 | 12509970.4879 | 31273558.5291 | -13.0000 | 208.0000 | 48609.0000 | 2288498.2500 | 119999998.0000 |
| Total Fwd Packets | 2209336.0000 | 11.0029 | 848.5188 | 1.0000 | 1.0000 | 2.0000 | 5.0000 | 219759.0000 |
| Total Length of Fwd Packets | 2209336.0000 | 650.4535 | 10800.0721 | 0.0000 | 12.0000 | 64.0000 | 169.0000 | 12900000.0000 |
| Flow Bytes/s | 2209336.0000 | 1530742.8257 | 28267768.9920 | -261000000.0000 | 111.6977 | 4482.5080 | 115063.4398 | 2071000000.0000 |
| Fwd Packets/s | 2209336.0000 | 42556.9449 | 199238.1271 | 0.0000 | 2.0099 | 41.3385 | 9478.6730 | 3000000.0000 |
| Flow IAT Mean | 2209336.0000 | 1025978.3964 | 4096093.9637 | -13.0000 | 81.0000 | 18033.1590 | 294028.4994 | 120000000.0000 |
| Flow IAT Std | 2209336.0000 | 1919820.0513 | 6295101.5035 | 0.0000 | 0.0000 | 10264.8019 | 595825.5351 | 84800261.5664 |
| Flow IAT Max | 2209336.0000 | 5503200.6595 | 16365211.0149 | -13.0000 | 173.0000 | 38504.0000 | 1961182.0000 | 120000000.0000 |
| Fwd Packet Length Mean | 2209336.0000 | 65.8603 | 208.0694 | 0.0000 | 6.0000 | 35.0000 | 51.0000 | 5940.8571 |
| Fwd Packet Length Std | 2209336.0000 | 77.0291 | 315.8611 | 0.0000 | 0.0000 | 0.0000 | 22.6274 | 7125.5968 |
| Fwd Packet Length Min | 2209336.0000 | 20.6818 | 63.8226 | 0.0000 | 0.0000 | 6.0000 | 38.0000 | 2325.0000 |

## 2. Skewness & Kurtosis

Skewness: 0 = symmetric, >1 / <-1 = heavily skewed (common and expected for network byte/duration counts). Kurtosis: excess kurtosis, 0 = normal-like tails, large positive = heavy-tailed / outlier-prone.

| index | skewness | kurtosis |
| --- | --- | --- |
| Destination Port | 1.7559 | 1.2655 |
| Flow Duration | 2.5650 | 5.1282 |
| Total Fwd Packets | 215.9353 | 48208.9108 |
| Total Length of Fwd Packets | 798.5345 | 924371.1153 |
| Flow Bytes/s | 42.9837 | 2376.9102 |
| Fwd Packets/s | 7.1296 | 60.2631 |
| Flow IAT Mean | 9.2251 | 116.2457 |
| Flow IAT Std | 5.7082 | 39.7340 |
| Flow IAT Max | 4.0464 | 16.6704 |
| Fwd Packet Length Mean | 8.1795 | 75.3282 |
| Fwd Packet Length Std | 9.4424 | 111.0564 |
| Fwd Packet Length Min | 18.5469 | 394.0290 |

## 3. Pearson Correlation Matrix

| index | Destination Port | Flow Duration | Total Fwd Packets | Total Length of Fwd Packets | Flow Bytes/s | Fwd Packets/s | Flow IAT Mean | Flow IAT Std | Flow IAT Max | Fwd Packet Length Mean | Fwd Packet Length Std | Fwd Packet Length Min |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Destination Port | 1.0000 | -0.1426 | -0.0051 | 0.0092 | 0.0693 | 0.3400 | -0.0885 | -0.0835 | -0.0756 | 0.1384 | 0.1296 | -0.0575 |
| Flow Duration | -0.1426 | 1.0000 | 0.0251 | 0.0794 | -0.0216 | -0.0854 | 0.4590 | 0.5975 | 0.6800 | 0.1598 | 0.2357 | -0.0899 |
| Total Fwd Packets | -0.0051 | 0.0251 | 1.0000 | 0.3802 | 0.0004 | -0.0022 | -0.0012 | -0.0005 | 0.0043 | -0.0004 | 0.0010 | -0.0034 |
| Total Length of Fwd Packets | 0.0092 | 0.0794 | 0.3802 | 1.0000 | 0.0022 | -0.0112 | 0.0061 | 0.0232 | 0.0487 | 0.1922 | 0.1660 | -0.0023 |
| Flow Bytes/s | 0.0693 | -0.0216 | 0.0004 | 0.0022 | 1.0000 | 0.3056 | -0.0136 | -0.0165 | -0.0182 | 0.0854 | 0.0773 | -0.0034 |
| Fwd Packets/s | 0.3400 | -0.0854 | -0.0022 | -0.0112 | 0.3056 | 1.0000 | -0.0535 | -0.0651 | -0.0718 | -0.0342 | -0.0259 | -0.0524 |
| Flow IAT Mean | -0.0885 | 0.4590 | -0.0012 | 0.0061 | -0.0136 | -0.0535 | 1.0000 | 0.7543 | 0.6880 | 0.0600 | 0.0631 | 0.0099 |
| Flow IAT Std | -0.0835 | 0.5975 | -0.0005 | 0.0232 | -0.0165 | -0.0651 | 0.7543 | 1.0000 | 0.8967 | 0.1615 | 0.1712 | -0.0059 |
| Flow IAT Max | -0.0756 | 0.6800 | 0.0043 | 0.0487 | -0.0182 | -0.0718 | 0.6880 | 0.8967 | 1.0000 | 0.2405 | 0.2624 | -0.0363 |
| Fwd Packet Length Mean | 0.1384 | 0.1598 | -0.0004 | 0.1922 | 0.0854 | -0.0342 | 0.0600 | 0.1615 | 0.2405 | 1.0000 | 0.9001 | 0.2412 |
| Fwd Packet Length Std | 0.1296 | 0.2357 | 0.0010 | 0.1660 | 0.0773 | -0.0259 | 0.0631 | 0.1712 | 0.2624 | 0.9001 | 1.0000 | -0.0752 |
| Fwd Packet Length Min | -0.0575 | -0.0899 | -0.0034 | -0.0023 | -0.0034 | -0.0524 | 0.0099 | -0.0059 | -0.0363 | 0.2412 | -0.0752 | 1.0000 |

### 3a. Highly Correlated Pairs (|r| >= 0.85)

| index | feature_a | feature_b | pearson_r |
| --- | --- | --- | --- |
| 0 | Fwd Packet Length Mean | Fwd Packet Length Std | 0.9001 |
| 1 | Flow IAT Std | Flow IAT Max | 0.8967 |

## 4. Variance & Sparsity Audit

`near_constant_flag` = normalized spread (variance/mean²) < 0.01. `sparse_flag` = more than 50% exact zeros.

| index | variance_raw | mean | cv_squared_normalized | zero_pct | near_constant_flag | sparse_flag |
| --- | --- | --- | --- | --- | --- | --- |
| Destination Port | 393964171.1021 | 9696.9610 | 4.1897 | 0.0709 | False | False |
| Flow Duration | 978035463072505.6250 | 12509970.4879 | 6.2495 | 0.0000 | False | False |
| Total Fwd Packets | 719984.0736 | 11.0029 | 5947.1993 | 0.0000 | False | False |
| Total Length of Fwd Packets | 116641557.3285 | 650.4535 | 275.6899 | 13.2280 | False | False |
| Flow Bytes/s | 799066763784357.2500 | 1530742.8257 | 341.0190 | 10.6693 | False | False |
| Fwd Packets/s | 39695831302.1644 | 42556.9449 | 21.9182 | 0.0022 | False | False |
| Flow IAT Mean | 16777985759480.6035 | 1025978.3964 | 15.9391 | 0.0000 | False | False |
| Flow IAT Std | 39628302939589.1797 | 1919820.0513 | 10.7519 | 32.2848 | False | False |
| Flow IAT Max | 267820131562739.2188 | 5503200.6595 | 8.8433 | 0.0000 | False | False |
| Fwd Packet Length Mean | 43292.8926 | 65.8603 | 9.9809 | 13.2280 | False | False |
| Fwd Packet Length Std | 99768.2075 | 77.0291 | 16.8144 | 64.2938 | False | True |
| Fwd Packet Length Min | 4073.3246 | 20.6818 | 9.5229 | 43.9561 | False | False |

## 5. Actionable Consolidation Insights

**a) Candidates for dropping:**

- Multicollinearity (keep the first of each flagged pair, drop the second unless domain reasoning says otherwise): `Flow IAT Max, Fwd Packet Length Std`
- Near-constant / low-information: none found at the configured threshold.
- Heavily sparse (>50% zeros — verify these are genuine empty-packet/no-payload signals, not a parsing artifact): `Fwd Packet Length Std`

**b) Model-specific impact:**

- **Random Forest:** Highly correlated feature pairs split importance between themselves at every tree split, diluting the reported importance of the true signal and letting trees overfit to whichever correlated feature happens to have a cleaner split point in a given bootstrap sample — this inflates apparent feature count without adding real separating power, and increases tree depth for no accuracy gain. Heavily right-skewed features (common here — byte counts, durations, packet rates) are handled natively by RF's split-based logic (it doesn't assume normality), so skew itself is not a concern for RF the way it would be for a linear model.
- **Isolation Forest:** This model isolates points via random axis-aligned splits, so near-constant features contribute almost nothing to isolation depth (dead weight that just adds noise to the random feature selection at each split) while extremely heavy-tailed features (high positive kurtosis) can dominate isolation paths — a handful of genuinely extreme benign flows may isolate as fast as real attacks, inflating false positives. Sparse (mostly-zero) columns similarly compress most of the mass into a single value, so splits on that feature rarely help isolate anything and should be scaled/transformed (e.g. log1p) or dropped if the sparsity isn't itself the attack signal.
