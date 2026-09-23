# Data Contracts — PS26145 Unidirectional Threat Detector

## FeatureVector

Computed per-flow by `FeatureEngine`, from forward-direction traffic only.
`unique_destinations` / `unique_dest_ports` are computed cross-flow (grouped
by `src_ip`) in `FeatureEngine.compute_batch()`; every other field is
per-flow.

| Field | Type | Source | Notes |
|---|---|---|---|
| `flow_id` | str | generated | UUID-prefixed, unique per engine instance |
| `timestamp` | str (ISO 8601) | `flow.last_seen` | |
| `packet_count` | int | count of packets in flow | forward-only |
| `byte_count` | int | sum of packet sizes | forward-only |
| `flow_duration` | float (µs) | `last_seen - first_seen` | **0 for single-packet flows** — this is a hard constraint of measuring only observed packet spread, not a bug |
| `packets_per_second` | float | `packet_count / duration_seconds` | 0.0 if duration is 0 |
| `avg_packet_size` | float | `byte_count / packet_count` | same formula as CICIDS's `Fwd Packet Length Mean` — not a separate concept |
| `iat_mean` | float (µs) | mean of inter-arrival gaps | 0.0 for flows with <2 packets |
| `iat_std` | float (µs) | stdev of inter-arrival gaps | 0.0 for flows with <2 packets |
| `unique_destinations` | int | distinct `dst_ip` for this `src_ip` | cross-flow |
| `unique_dest_ports` | int | distinct `dst_port` for this `src_ip` | cross-flow; drives the `PORT_SCAN` rule override (see below) |
| `protocol` | enum | `TCP` \| `UDP` | |
| `syn_count` | int | count of packets with SYN flag set | present in contract, **not fed to the RF/IF models** (see Model Input below) |
| `dst_port` | int | `Flow.dst_port` | |
| `flow_bytes_per_second` | float | `byte_count / duration_seconds` | 0.0 if duration is 0 |
| `fwd_packet_length_min` | int | `min(packet.packet_size for packet in flow.packets)` | |

## CICIDS-name ↔ contract-name mapping

| CICIDS/Kaggle name | Contract name |
|---|---|
| Destination Port | `dst_port` |
| Flow Duration | `flow_duration` |
| Total Fwd Packets | `packet_count` |
| Total Length of Fwd Packets | `byte_count` |
| Flow Bytes/s | `flow_bytes_per_second` |
| Flow Packets/s | `packets_per_second` |
| Flow IAT Mean / Std | `iat_mean` / `iat_std` |
| Fwd Packet Length Mean | `avg_packet_size` (identical formula, not a new field) |
| Fwd Packet Length Min | `fwd_packet_length_min` |
| SYN Flag Count | `syn_count` |

## Model input (RF + Isolation Forest)

The trained models consume exactly **10 of the 14 fields above**, in this
order (confirmed from the models' own `feature_names_in_`, not assumed):

```
Destination Port, Flow Duration, Total Fwd Packets, Total Length of Fwd Packets,
Flow Bytes/s, Fwd Packets/s, Flow IAT Mean, Flow IAT Std,
Fwd Packet Length Mean, Fwd Packet Length Min
```

`syn_count`, `unique_destinations`, `unique_dest_ports`, and `protocol` are
**not** model inputs — they remain in the contract for evidence generation
and the `PORT_SCAN` rule override in `inference_client.py`
(`unique_dest_ports >= 10 and packet_count <= 5`). The RF model cannot
detect port scans on its own — see Section 5 of the project memory for why
(structural: the model needs `Total Fwd Packets == 1` and nonzero
`Flow Duration` simultaneously, which is definitionally impossible for a
real single-packet flow in this system).

`Total Backward Packets` and `Down/Up Ratio` are **never** valid features —
structurally unobservable on a unidirectional link. Never add them back.

## Model output → threat_class mapping

The trained RF model's `classes_` do not match the frozen enum directly —
translated in `inference_client.py`:

| Model label | `ThreatClass` |
|---|---|
| Normal Traffic | `BENIGN` |
| Port Scanning | `PORT_SCAN` (via rule, not RF) |
| DDoS | `SYN_FLOOD` |
| Bots | `C2_BEACONING` |

## InferenceResponse

| Field | Type | Notes |
|---|---|---|
| `flow_id` | str | |
| `threat_class` | enum | `BENIGN` \| `C2_BEACONING` \| `PORT_SCAN` \| `SYN_FLOOD` — frozen, do not add `DDOS`/`BOT` naming |
| `confidence` | float [0,1] | RF `predict_proba` max, or rule-based estimate for `PORT_SCAN` |
| `anomaly_score` | float [0,1] | Isolation Forest `score_samples`, sigmoid-normalized around the calibrated threshold (`-0.447`) |
| `top_features` | list[str] | RF feature importances, or `["unique_dest_ports", "packet_count"]` for rule-based `PORT_SCAN` |
| `model_version` | str | `"rf-if-v3"` |
