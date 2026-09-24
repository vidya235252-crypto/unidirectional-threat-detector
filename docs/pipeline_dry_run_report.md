# Unidirectional Threat Detector — Pipeline Data Flow & Dry-Run Report

**Purpose of this document:** trace one flow record end-to-end through every branch of the pipeline — exact input shape, exact output shape at each stage, and how the Alert Engine consolidates four independent branch outputs into one final decision. Every field name and function signature below is copied directly from the current codebase, not paraphrased.

---

## 1. The two inputs every flow carries

Every flow entering the pipeline is split into **two separate objects at the source** — this separation is deliberate and load-bearing for the whole design (see §6):

```
FlowRecord
├── feature_vector: dict[str, float]   → goes ONLY to RF / IForest
└── flow_meta: dict                    → goes to DGA/JA3/behavioral branches
                                          and the Alert Engine's fusion logic
```

### 1a. `feature_vector` — the frozen 10-field ML schema

This is the **only** thing RF and IForest ever see. Exact field names, exact order:

| # | Field name | Type | Unit / note |
|---|---|---|---|
| 1 | `Destination Port` | int | — |
| 2 | `Flow Duration` | float | **microseconds** (CICFlowMeter convention — training data's source tool) |
| 3 | `Total Fwd Packets` | int | — |
| 4 | `Total Length of Fwd Packets` | float | bytes |
| 5 | `Flow Bytes/s` | float | — |
| 6 | `Fwd Packets/s` | float | — |
| 7 | `Flow IAT Mean` | float | inter-arrival time, microseconds |
| 8 | `Flow IAT Std` | float | microseconds |
| 9 | `Fwd Packet Length Mean` | float | bytes |
| 10 | `Fwd Packet Length Min` | float | bytes |

**Do not change this list without retraining** — RF and IForest were both fit against this exact 10-column order.

### 1b. `flow_meta` — identity/context, never fed to a model

| Field | Type | Note |
|---|---|---|
| `source_ip` | str | **Never appears anywhere in `feature_vector`.** Carried as a sibling identity parameter to every branch. |
| `dest_ip` | str | Reserved in the behavioral contract; not yet used in scoring. |
| `timestamp` | float (epoch) or ISO str | Branch-dependent format — see §2–5. |
| `flow_id` | str | Unique per flow; threads through every branch into the final Alert. |

**Verified constraint (checked directly in code, not a bug — must hold end-to-end):** `source_ip` is never part of any numeric feature vector or ML input anywhere in this pipeline. This is what lets the Alert Engine correlate signals across branches without the models ever learning to memorize IP addresses.

---

## 2. Branch 1 — Random Forest + Isolation Forest (`network_ml`)

**Input:** `feature_vector` reshaped to a single row, shape `(1, 10)`.

**RF output** — `rf_model.predict(v)`:
```
rf_threat_class ∈ {"Normal Traffic", "DDoS", "Port Scanning", "Bots"}
rf_confidence: float
```

**IForest output** — `if_model.score_samples(log1p_transform(v))`:
```
iforest_raw_score: float   # continuous, NOT -1/+1. Lower = more anomalous.
```
The log1p transform is applied to 7 of the 10 fields before scoring (`Flow Duration`, `Total Fwd Packets`, `Total Length of Fwd Packets`, `Flow Bytes/s`, `Fwd Packets/s`, `Flow IAT Mean`, `Flow IAT Std`), each clipped at 0 first.

**How this feeds the Alert Engine — `process_network_ml()` payload:**
```python
{
    "source_ip": str, "timestamp": float, "flow_id": str,
    "rf_threat_class": str,
    "rf_confidence": float,
    "iforest_raw_score": float,   # required only when rf_threat_class == "Bots"
    "evidence": dict,
}
```

**Decision logic inside the engine (exact, from source):**
- `rf_threat_class == "Normal Traffic"` → no signal, nothing registered.
- `rf_threat_class in ("DDoS", "Port Scanning")` → registers `ML_BRANCH_SIGNAL` directly. No IForest gate — these classes hit F1 ≥ 0.99 standalone on the held-out test set.
- `rf_threat_class == "Bots"` → **gated by IForest.** If `iforest_raw_score < calibrated_threshold` (currently ≈ **-0.4470**) → corroborated, registers `ML_BRANCH_SIGNAL`. If not corroborated → RF's label and confidence are **preserved, not overwritten**, no signal registered, logged instead to `engine.near_misses` for audit. (IForest was calibrated for ≥90% Bots recall, not 100% — an uncorroborated Bot can be real.)

---

## 3. Branch 2 — DGA / DNS Tunneling (`dns_branch`)

**Real entry point:** `classify_dns_query(domain, query_type, timestamp, src_ip)` from `detector_interfaces.py`.

**Input:**
```
domain: str            # e.g. "xk29fj2q8zpmw1n.net"
query_type: str         # accepted but NOT currently used in scoring
timestamp: str           # ISO format
src_ip: str
```

**Internal order of checks** (cheap → expensive):
1. Blocklist match against the Bambenek feed → instant `flagged=True, confidence=1.0`.
2. Allowlist bypass (top-10,000 Tranco domains, subdomain-aware) → `flagged=False, reason="allowlisted"`.
3. Statistical fallback: Shannon entropy + bigram log-probability, each compared against a calibrated threshold.
4. **Separately**, a streaming per-`src_ip` rolling window (5s) checks DNS-tunneling shape: `high_query_rate` (≥20 queries/5s) and `long_subdomain` (≥30 chars).

**Output (fixed contract):**
```python
{
    "flagged": bool,
    "reason": str,          # e.g. "blocklist_match", "entropy+ngram", "allowlisted", "clean"
    "confidence": float,
    "entropy_score": float,
    "ngram_score": float,
}
```

**Feeds the Alert Engine as** `process_dns_branch()` payload:
```python
{
    "source_ip": str, "timestamp": float, "flow_id": str,
    "dns_flag": "DGA" | "DNS_TUNNELING" | None,   # None → no signal registered
    "domain": str,
}
```

**One-time cost, not per-call:** the first call to `classify_dns_query()` in a process's lifetime loads Bambenek + Tranco and builds the n-gram model (~seconds). This is cached at module level after that — every subsequent call is pure lookup/scoring (measured: **p50 = 6.9µs**).

---

## 4. Branch 3 — JA3/JA3S TLS Fingerprint (`tls_branch`)

**Real entry point:** `classify_tls_session(fingerprint, transport, role, timestamp, src_ip)`.

**Input:**
```
fingerprint: str    # already-computed 32-hex-char MD5 hash — NOT raw ClientHello fields
transport: "tls" | "quic"
role: "client" | "server"
timestamp: str
src_ip: str
```
GREASE values (RFC 8701) are stripped before hashing upstream — this function receives an already-clean hash, pure blocklist lookup.

**Output (fixed contract):**
```python
{
    "flagged": bool,
    "reason": str,             # "blocklist_match" | "clean" | "invalid_transport" | "invalid_role" | "invalid_fingerprint_format"
    "confidence": float,       # 1.0 on match, 0.0 otherwise
    "matched_hash": str | None,
}
```

**Feeds the Alert Engine as** `process_tls_branch()` payload:
```python
{
    "source_ip": str, "timestamp": float, "flow_id": str,
    "ja3_match": bool,
    "ja3_hash": str,
}
```
No JA3 match → no signal registered. Measured latency is the fastest of all four branches (**p50 = 1.5µs**) — it's a pure set lookup, no scoring.

---

## 5. Branch 4 — Behavioral / Data Exfiltration (`behavioral_branch`)

**Real entry point:** `classify_outbound_behavior(tracker, ip_address, timestamp, byte_count, flow_duration, pps, dest_ip)`.

**Input:**
```
tracker: PerIPTracker       # ONE long-lived instance owned by the Alert Engine —
                             # never recreated per call, or every entity resets to cold-start
ip_address: str
timestamp: float
byte_count: int
flow_duration: float        # SECONDS — must be converted from the raw microsecond field
pps: float
dest_ip: str                 # reserved, not yet used in scoring
```

**Two independent internal heuristics, merged into ONE signal before leaving this function:**
1. **Volume baseline drift** — streaming EWMA mean/variance per entity (O(1) memory, no history list stored). Z-score computed against the *pre-update* baseline, then state updates. Cold-start entities (< 10 prior flows) are never scored, only used to build the baseline (`status = "INSUFFICIENT_HISTORY"`). Once past cold-start, `status = "SCORED"`; triggers if `z_score > 3.0`.
2. **Low-and-slow** — stateless: `flow_duration > 3600s AND pps < 2.0`.

These two are deliberately merged into a single `BEHAVIORAL_SIGNAL` category (not two) — otherwise a correlated pair of outbound-metadata heuristics could reach the fusion engine's "2+ categories" escalation bar entirely on its own, with zero ML/DNS/TLS corroboration.

**Output (fixed contract):**
```python
{
    "event_type": "BEHAVIORAL_SIGNAL",
    "entity_id": str,
    "timestamp": float,
    "alert_triggered": bool,
    "metrics": {
        "baseline_drift": {"triggered": bool, "z_score": float, "status": "INSUFFICIENT_HISTORY" | "SCORED"},
        "low_and_slow":   {"triggered": bool, "duration": float, "pps": float},
    },
}
```

**Feeds the Alert Engine as** `process_behavioral_branch()` payload — same field names as the raw input above, plus `flow_id` and optional `evidence`. A cold-start (`INSUFFICIENT_HISTORY`) result is never logged as a near-miss — it's routine per-entity ramp-up, not evidence of anything.

**`feature_vector_translator.py`** exists specifically because the live flow engine hands the pipeline a 10-field ML vector + `flow_meta`, not byte_count/flow_duration/pps directly — `translate_feature_vector_to_behavioral_payload()` builds this branch's payload from those two objects, doing the microsecond→second conversion explicitly (`duration_unit="microseconds"` default) and raising loudly (`KeyError`) if a required field is missing, rather than silently defaulting.

---

## 6. The Alert Engine — how four outputs become one decision

`SecurityAlertEngine` correlates all four branch outputs **per `source_ip`**, inside a **60-second rolling window** (lazy-pruned: an IP's stale entries are only dropped when that IP is touched again).

**Core rule, verified directly in `_evaluate_fusion()`:**

```
categories_present = distinct signal_type values currently in this source_ip's window

if len(categories_present) >= 2:
    → HIGH severity, alert_type = "DATA_EXFILTRATION"
    → gated by a cooldown (default = window length, 60s) so the same
      two stale signals can't re-fire an identical HIGH alert on every
      subsequent unrelated event for that IP
else (exactly one category fired):
    → LOW severity, alert_type = f"{signal_type}_DETECTION"
    → never discarded — a single signal still produces a standalone alert
```

This counts **distinct categories**, not raw event volume — three DDoS packets from the ML branch alone is still one category (`ML_BRANCH_SIGNAL`), not three. The escalation rule is specifically about cross-layer corroboration (ML + DNS + TLS + Behavioral), not noise volume within one layer.

**Final output shape — the `Alert` object:**
```python
{
    "severity": "LOW" | "HIGH",
    "alert_type": str,           # "DATA_EXFILTRATION" or "<SIGNAL>_DETECTION"
    "source_ip": str,
    "timestamp": float,
    "signals": list[str],        # which categories contributed
    "evidence": list[dict],      # one dict per contributing event, full audit trail
    "flow_ids": list[str],
}
```

Everything that fired but didn't escalate is still retrievable: `engine.alert_log` (every alert, low + high) and `engine.near_misses` (uncorroborated Bots, logged with reason — never silently dropped).

---

## 7. Worked dry-run example — one source IP, three flows

**Scenario:** source IP `10.0.0.47` sends three flows within a 40-second span.

### Flow 1 — t=0s, a port scan

**Input `feature_vector`:**
```json
{"Destination Port": 445, "Flow Duration": 1200, "Total Fwd Packets": 2,
 "Total Length of Fwd Packets": 120, "Flow Bytes/s": 100000.0, "Fwd Packets/s": 1666.7,
 "Flow IAT Mean": 600.0, "Flow IAT Std": 50.0, "Fwd Packet Length Mean": 60.0,
 "Fwd Packet Length Min": 60.0}
```
→ RF output: `rf_threat_class = "Port Scanning"`, `rf_confidence = 0.97`
→ No IForest gate needed for this class → **`ML_BRANCH_SIGNAL` registered.**
→ Window for `10.0.0.47`: `{ML_BRANCH_SIGNAL}` → 1 category → **LOW alert**, `alert_type = "ML_BRANCH_SIGNAL_DETECTION"`.

### Flow 2 — t=15s, a DGA-looking DNS query from the same IP

**Input:** `domain = "xk29fj2q8zpmw1n.net"`, `src_ip = "10.0.0.47"`
→ Entropy + n-gram fallback fires → `flagged=True, reason="entropy+ngram", confidence=0.9`
→ `dns_flag = "DGA"` → **`DNS_BRANCH_SIGNAL` registered.**
→ Window for `10.0.0.47`: `{ML_BRANCH_SIGNAL, DNS_BRANCH_SIGNAL}` → **2 distinct categories.**
→ **Escalates to HIGH**, `alert_type = "DATA_EXFILTRATION"`, `signals = ["DNS_BRANCH_SIGNAL", "ML_BRANCH_SIGNAL"]`, `evidence` contains both flows' full context, `flow_ids = [flow_1_id, flow_2_id]`.
→ `_last_escalation["10.0.0.47"] = 15.0` recorded — cooldown of 60s now active.

### Flow 3 — t=25s, same IP, a JA3 blocklist match

→ `ja3_match = True` → **`TLS_BRANCH_SIGNAL` registered** into the window.
→ Window now has 3 categories — would normally re-qualify for HIGH, **but** `(25 - 15) = 10s < 60s cooldown` → **suppressed.** No duplicate HIGH alert. The signal is still logged in the window and would contribute if a fresh escalation check runs after the cooldown expires.

**End result for this IP across the 40s span:**
- 1 LOW alert (flow 1, standalone)
- 1 HIGH `DATA_EXFILTRATION` alert (flow 2, corroborated by flow 1)
- 1 suppressed re-escalation (flow 3, cooldown-protected)
- `engine.near_misses` — empty for this IP (no uncorroborated Bots occurred)

This is the exact mechanism that turns four independently-computed branch outputs into one prioritized, de-duplicated alert stream for the dashboard.

---

## 8. Measured throughput

The current production streaming flow is benchmarked through the same
`stream_scenario()` path used by the backend:

ScenarioLoader → FlowEngine → FeatureEngine → Behavioral/Exfiltration
detector → Random Forest / Isolation Forest inference → Deduplication →
AlertEngine.

The benchmark runs the current scenario streams repeatedly without the
dashboard's artificial scenario playback delay.

### End-to-end streaming benchmark

| Scenario | Flows processed | Throughput |
|---|---:|---:|
| Benign | 100 | 10.6 flows/sec |
| Port Scan | 4,000 | 45.4 flows/sec |
| SYN Flood | 100 | 10.4 flows/sec |
| C2 Beaconing | 100 | 10.6 flows/sec |
| Data Exfiltration | 100 | 7,046.7 flows/sec |
| **Aggregate** | **4,400** | **37.8 flows/sec** |

**Aggregate measured throughput: 37.8 flows/sec.**

The benchmark is a single-process, sequential measurement of the current
streaming implementation. The scenario files contain different numbers of
flows, so the aggregate figure is weighted by the number of flows processed
in each scenario. The port-scan scenario contributes the largest share of
the measured workload with 4,000 flows.

This measurement represents detector processing through the current
streaming orchestrator and does not include the dashboard's artificial
playback delay.

### Component throughput

The existing component benchmarks remain useful for understanding the
relative cost of individual detection stages:

- RF micro-batched inference: 1,329.7 flows/sec
- Isolation Forest micro-batched inference: 1,990.1 flows/sec
- DGA/DNS detector: 77,305.6 flows/sec
- JA3 detector: 488,768.3 flows/sec
- Behavioral/Exfiltration detector: 260,854.2 flows/sec

These component measurements should not be presented as the end-to-end
throughput of the current streaming pipeline.

---

## 9. Current implementation status

The previous 11-field feature-vector mismatch described in this document
is no longer the current state of the implementation.

The current streaming pipeline uses the existing model-compatible feature
construction and successfully exercises the production inference path for
the flow scenarios.

The current integrated scenario set is:

- Benign
- Port Scan
- SYN Flood
- C2 Beaconing
- Data Exfiltration
- DGA DNS Tunneling
- Malicious TLS

The flow scenarios use the streaming orchestrator, while DGA/DNS tunneling
and malicious TLS are handled by their dedicated secondary detector
pipelines.

The current benchmark establishes a measured end-to-end flow-processing
throughput of **37.8 flows/sec** for the tested workload.