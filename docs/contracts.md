# PS26145 — Systems ↔ AI Contract & Context

**For:** Teammate 1 (AI/ML)
**From:** Teammate 2 (Systems)
**Status as of Day 1 completion**

This is everything you need to know about what I've built so far, what's frozen, what's assumed, and what still needs your input.

---

## 1. The Frozen Contracts (do not change without syncing)

### Feature Vector (what I send you)

Flat JSON, no nesting. `flow_duration` is in **microseconds**, matching raw CICIDS `Flow Duration` values — not seconds.

```json
{
  "flow_id": "f_10293",
  "timestamp": "2026-09-11T10:15:32.000Z",
  "packet_count": 42,
  "byte_count": 8234,
  "flow_duration": 5000000.0,
  "packets_per_second": 8.4,
  "avg_packet_size": 196.2,
  "iat_mean": 1.24,
  "iat_std": 0.31,
  "unique_destinations": 1,
  "unique_dest_ports": 3,
  "protocol": "TCP",
  "syn_count": 1
}
```

`protocol` is strictly `"TCP"` or `"UDP"` (enum-enforced on my side, invalid values rejected).

### Inference Response (what you send back)

```json
{
  "flow_id": "f_10293",
  "threat_class": "C2_BEACONING",
  "confidence": 0.96,
  "anomaly_score": 0.91,
  "top_features": ["iat_std", "unique_destinations"],
  "model_version": "v1"
}
```

`threat_class` must be one of: `BENIGN`, `C2_BEACONING`, `PORT_SCAN`, `SYN_FLOOD` — nothing else, enum-enforced on my side too. `confidence` and `anomaly_score` must both be in `[0, 1]`.

Both contracts are implemented as Pydantic models in code (`backend/app/contracts/feature_vector.py`, `backend/app/contracts/inference_response.py`) — not just docs, so they're actually enforced, not just agreed in principle.

---

## 2. Important assumptions baked into the contract (please read, these affect your training data)

- **`packet_count` / `byte_count` are forward-direction only.** My flow engine only ever observes one direction of traffic (that's the core "unidirectional" premise of the whole project) — so these fields represent forward packets/bytes only, not fwd+bwd summed. If you're deriving these from CICIDS `Total Fwd Packets` + `Total Backward Packets`, **don't sum them** — use forward-only columns to match what I'll actually be sending you at inference time.
- **`protocol` is not always real data.** The CICIDS2017 cleaned dataset we're using has no Protocol column at all. For benign/port-scan rows sourced from that dataset, I'm assigning `"TCP"` by convention (documented assumption, not fabricated per-row data). SYN-flood and C2-beaconing are fully synthetic anyway, also assigned `TCP` (accurate for both — SYN flood is TCP-specific by definition, C2 beaconing here is modeled as HTTPS-based).
- **`syn_count` is not available from the CICIDS dataset either.** I checked the actual column schema — `SYN Flag Count` was dropped during their preprocessing (FIN/PSH/ACK survived, SYN didn't). This means if you're training directly on their CSV, you structurally cannot use a real syn_count feature for any row from that source. For the port-scan/benign scenario files I generate, I'm assigning `syn_count` via a domain heuristic (e.g., port-scan ≈ every packet is a SYN, benign ≈ 1 handshake) — not real per-row data. Worth deciding together whether your model should even weight `syn_count` heavily for classes sourced from this dataset, versus leaning on it more for SYN-flood specifically (which is fully synthetic and has a clean, correct syn_count by construction).

---

## 3. Scenario Files — what exists right now

All 4 live at `data/scenarios/*.jsonl`, one JSON object per line, one line per **packet** (not per flow):

```json
{"timestamp": "2026-09-11T10:15:32.000Z", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51000, "dst_port": 443, "protocol": "TCP", "packet_size": 512, "syn_flag": false}
```

| File | Status |
|---|---|
| `syn_flood.jsonl` | **Final.** Fully synthetic — 500 packets, sub-5ms gaps, spoofed source IPs, all SYN flags set. |
| `c2_beaconing.jsonl` | **Final.** Fully synthetic — 12 packets, ~30s intervals with small jitter, near-machine-perfect periodicity. |
| `benign.jsonl` | **Placeholder.** Currently synthetic (one HTTPS-like session, 20 packets). Will be swapped for CICIDS-derived data once we confirm which columns/rows to use. |
| `port_scan.jsonl` | **Placeholder.** Currently synthetic (one source hitting 40 sequential ports). Same caveat — pending CICIDS `Attack Type` verification (see below). |

I generate synthetic packet sequences even for CICIDS-sourced scenarios, because CICIDS only has flow-level aggregate stats, never raw packets — so "real data" here means the packet sequence is constructed to reproduce a real row's statistics, not that literal packets from 2017 are being replayed.

---

## 4. Open item — needs your check

The CICIDS2017 cleaned dataset's `Label` column was renamed to `Attack Type` and coarsened during their preprocessing (similar attack types grouped, rare types like Infiltration/Heartbleed dropped entirely). **I don't yet know if `PortScan` survived as its own distinct value.** Can you run:

```python
print(df['Attack Type'].unique())
```

and send me the output? If `PortScan` is there as its own category, we filter on it directly for real rows. If it's been merged into something broader, we'll likely keep `port_scan.jsonl` fully synthetic like SYN-flood/C2 rather than approximating from a merged category.

---

## 5. Division of ownership (reminder)

- **Contracts** (`app/contracts/*.py`) — I own the code, but changes need both of us to agree first.
- **Scenario files** — I own generation/format; you may want your own copy for offline training, which is fine, just flag if you need a different structure for that (training pipeline needs can differ from my live replay needs).
- **Your real inference service** — up to you how it's implemented (HTTP endpoint, importable function, etc.) — let me know your plan before Day 6 so I can build `inference_client.py` to match.

From: Teammate 2 (Systems) Status as of: End of Day 2

This is a full update — what exists, what's frozen, what changed since the last version, what's still open, and what I found that affects your training data.

1. The Frozen Contracts (unchanged, still the source of truth)
Feature Vector (what I send you)
json
{
  "flow_id": "f_10293",
  "timestamp": "2026-09-11T10:15:32.000Z",
  "packet_count": 42,
  "byte_count": 8234,
  "flow_duration": 5000000.0,
  "packets_per_second": 8.4,
  "avg_packet_size": 196.2,
  "iat_mean": 1.24,
  "iat_std": 0.31,
  "unique_destinations": 1,
  "unique_dest_ports": 3,
  "protocol": "TCP",
  "syn_count": 1
}

Flat, no nesting. flow_duration/iat_mean/iat_std are all in microseconds. protocol is strictly "TCP" or "UDP".

Inference Response (what you send back)
json
{
  "flow_id": "f_10293",
  "threat_class": "C2_BEACONING",
  "confidence": 0.96,
  "anomaly_score": 0.91,
  "top_features": ["iat_std", "unique_destinations"],
  "model_version": "v1"
}

threat_class must be one of: BENIGN, C2_BEACONING, PORT_SCAN, SYN_FLOOD. confidence/anomaly_score both [0, 1].

Both are real, enforced Pydantic models in code now (backend/app/contracts/), not just docs.

2. Important assumptions baked into the contract (still relevant)
packet_count/byte_count are forward-direction only — matches the unidirectional premise, my flow engine only ever observes one direction.
protocol is assigned by scenario type for CICIDS-sourced rows (no Protocol column exists in that dataset) — "TCP" for all four scenario types currently.
syn_count from CICIDS-sourced data is uncertain — see Section 4, this is now an open dispute, not a settled assumption.
3. What I built in Day 2 — the full live pipeline now works end-to-end

As of today, the entire chain is real, tested code, not just planning:

scenario .jsonl file → ScenarioLoader → FlowEngine → FeatureEngine → FeatureVector

Concretely:

Packet ingestion (app/ingestion/scenario_loader.py) — reads scenario files, safely skips malformed lines with logging.
Directional flow engine (app/core/flow_engine.py) — groups packets into flows by the 5-tuple key, never merges with reverse-direction traffic (this is now a formally tested guarantee, see below).
Time-window logic — flows close either when they go stale (no new packet within the configured window) or at end-of-replay.
Feature engine (app/core/feature_engine.py) — computes all 10 contract fields per flow, including the cross-flow unique_destinations/unique_dest_ports aggregation your original contract doc specified (grouped by source IP, computed once, joined back to every flow from that source).
Orchestrator (app/pipeline/orchestrator.py) — wires all of the above into one function: give it a scenario file, get back a list of FeatureVectors.
Formal tests (backend/tests/test_feature_engine.py) — 4 passing pytest tests, including one that specifically proves a forward packet and its reply never get merged into the same flow. This is now a repeatable, automated proof of the core "unidirectional" claim, not just a design description.
4. New open dispute — needs resolving together, affects your training data directly

There's a real disagreement between what I verified from Kaggle's published dataset metadata and what you're reporting from your actual extracted file (cicids2017_12_features.csv):

My check (against Kaggle's Croissant metadata for the dataset page) found no Label, SYN Flag Count, or Down/Up Ratio columns.
Your analysis (apparently run directly against your real extracted CSV) reportedly shows all three present with real, non-null statistics matching published CICIDS2017 distributions.

These can't both be right about the same file. Possible explanation: Kaggle's metadata may describe a different variant/version than the actual CSV you downloaded — metadata pages can be stale or incomplete.

I have not yet personally verified your actual file or your analysis report — I've only seen descriptions of it, not the raw output. Before we lock anything based on this:

Please send me the actual dataset_analysis_report.txt file, or the raw output of:

python
print(df.columns.tolist())
print(df[['Label', 'SYN Flag Count', 'Down/Up Ratio']].describe())

Once I see the real thing, I'll update this document and drop the "assumed missing" caveats if they're confirmed present — that would actually be good news, since real syn_count data beats the synthetic heuristic I'm currently using for the SYN-flood scenario.

Known, separate bug in prepare_dataset.py (flagged earlier, confirm it's fixed): the script's SELECTED_COLUMNS list included "Label" — should be "Attack Type", since that's the actual column name in this dataset (confirmed independently from Kaggle's metadata, this part isn't in dispute). Also flagged: the script as originally shared doesn't actually filter down to a specific row count — it processes and saves the full dataset with column filtering only. Worth confirming whether a separate step handles the row selection down to 12.

5. Scenario Files — current status (one bug fixed today, worth knowing about)

All 4 live at data/scenarios/*.jsonl, packet-level JSONL format (one line per packet):

File	Status
syn_flood.jsonl	Final, fixed today. Originally had per-packet spoofed source IP/port, which meant every packet formed its own isolated one-packet flow — the flood pattern was completely invisible to the feature engine (each vector showed packet_count: 1). Fixed to use one consistent attacking source; now correctly produces packet_count: 500, syn_count: 500, high packets_per_second, low/regular iat_mean.
c2_beaconing.jsonl	Final, verified working. 12 packets, ~30s intervals. iat_std is only ~0.7% of iat_mean — clean periodicity signature.
benign.jsonl	Placeholder, currently synthetic (one 20-packet HTTPS-like session). Fixed earlier to use one persistent flow instead of 20 separate ones. Still pending your real-data swap once column dispute above is resolved.
port_scan.jsonl	Placeholder, currently synthetic (40 sequential ports). Produces unique_dest_ports: 40 correctly on each single-packet flow — proves the cross-flow aggregation works. Still pending real-data swap, and pending your confirmation of whether PortScan survived as its own Attack Type category.
6. What I need from you to move forward cleanly
The real column verification — Section 4, actual file/output, not a description.
Confirm prepare_dataset.py's Label→Attack Type fix landed, and clarify the 12-row filtering step.
df['Attack Type'].unique() output — still needed to know if PortScan is its own category.

None of these block my work right now — Day 3 (mock inference, evidence generation, alert engine) doesn't depend on the CICIDS swap. But the sooner these are settled, the smoother Day 6 integration will go.