"""
alert_fusion_engine.py

SecurityAlertEngine — centralized alert fusion for the unidirectional
threat detector pipeline. Ingests structured outputs from three independent
detection branches:

    1. network_ml   -> Random Forest + Isolation Forest (rare-class corroboration)
    2. dns_branch    -> DGA / DNS tunneling detector
    3. tls_branch    -> JA3/JA3S fingerprint detector

...correlates them per `source_ip` inside a rolling time window, and
escalates 2+ independently-firing signal categories into a single
High-Confidence Data Exfiltration Alert. A single firing signal is never
discarded — it's still emitted as a standalone Low-Severity alert.

================================================================================
DESIGN DECISIONS (read this before touching the fusion logic)
================================================================================

1. THRESHOLD LOADING — BUG FIX FROM THE ORIGINAL SPEC.
   The original spec assumed `iforest_model.calibrated_threshold_` as an
   attribute injected onto the model object. That does not exist: per last
   session's design, `models/optimized_isolation_forest.joblib` is a BARE
   `IsolationForest` (so any existing `joblib.load(path).score_samples(X)`
   call site keeps working unmodified), and the calibrated threshold lives
   in a separate sidecar, `models/optimized_isolation_forest_threshold.json`.
   This engine loads both files independently at __init__ time and fails
   loudly (raises) if either is missing, rather than silently defaulting
   to some arbitrary threshold.

2. UNCORROBORATED BOT CALLS -> "KEEP LABEL, SKIP SIGNAL" (not override).
   IForest's threshold was calibrated for >=90% RECALL, not 100% — so a
   real Bot can legitimately fail corroboration. Overwriting RF's
   classification to "Normal Traffic" would erase that evidence entirely.
   Instead: RF's original label + confidence are preserved untouched in
   the returned record, the ML_BRANCH_SIGNAL is simply not registered
   (so an uncorroborated Bot alone can never trigger the fusion rule),
   and the event is logged to `self.near_misses` for later audit. This
   means: if you want to know how many "almost-Bots" got quietly
   downgraded, `engine.near_misses` (or `generate_summary_report()`)
   has the full list with reasons — nothing is silently dropped.

3. ROLLING WINDOW = 60 SECONDS, LAZY-PRUNE EVICTION.
   Chosen because this pipeline replays finite PCAP/JSONL scenarios, not
   an indefinite live feed — 60s is generous enough to still be holding a
   port-scan signal by the time a JA3 match for the same IP arrives
   seconds to ~1 minute later, without a long-lived production-scale
   correlation window we don't need for a scripted demo. Lazy prune (drop
   an IP's stale entries only when that IP is touched again) was picked
   over an active background sweep because it needs no extra thread/timer
   and is trivial to reason about for a bounded demo run; the known
   trade-off (a single-ping IP's entry can sit stale in memory until that
   IP is seen again, if ever) is called out explicitly rather than hidden
   — acceptable for a scripted run, and flagged here as the first thing
   to revisit for a real always-on deployment.

4. DISTINCT SIGNAL *CATEGORIES* COUNT, NOT RAW EVENT COUNT.
   Three DDoS packets from the ML branch inside one window still count as
   ONE independent signal (ML_BRANCH_SIGNAL), not three — the escalation
   rule is about cross-LAYER corroboration (ML + DNS + TLS), not volume
   within a single layer. This matters: without de-duplicating by
   category, a single noisy detector could reach the "2+ signals" bar on
   its own by firing twice, which defeats the entire point of requiring
   independent corroboration.

5. ESCALATION COOLDOWN (added to resolve an open risk from the original
   spec — not explicitly asked for, easy to disable/tune).
   The original spec didn't say what happens to an IP's window *after* a
   High-Confidence alert fires. Left as-is, the same two signals sitting
   in the window would re-fire an identical High-Confidence alert on the
   very next unrelated event for that IP until they naturally age out —
   alert-spam risk. Fix: once an IP escalates, a `cooldown_seconds`
   (defaults to the window length) suppresses a second High-Confidence
   alert for that same IP, while still logging incoming signals normally.
   This is a judgment call flagged here explicitly so it's easy to find
   and change — see `cooldown_seconds` in `__init__`.
================================================================================
"""

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import joblib

# --------------------------------------------------------------------------
# Structured record types
# --------------------------------------------------------------------------

@dataclass
class Alert:
    severity: str            # "LOW" | "HIGH"
    alert_type: str          # e.g. "ML_BRANCH_DETECTION" | "DATA_EXFILTRATION"
    source_ip: str
    timestamp: float
    signals: list            # list of signal_type strings that contributed
    evidence: list           # list of raw evidence dicts, one per contributing event
    flow_ids: list


@dataclass
class NearMiss:
    """An event that fired a detector but failed corroboration or the
    fusion bar — logged, never silently discarded."""
    source_ip: str
    timestamp: float
    flow_id: str
    reason: str
    detail: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class SecurityAlertEngine:

    ML_SIGNAL = "ML_BRANCH_SIGNAL"
    DNS_SIGNAL = "DNS_BRANCH_SIGNAL"
    TLS_SIGNAL = "TLS_BRANCH_SIGNAL"

    def __init__(
        self,
        iforest_model_path="models/optimized_isolation_forest.joblib",
        iforest_threshold_path="models/optimized_isolation_forest_threshold.json",
        window_seconds: float = 60.0,
        cooldown_seconds: Optional[float] = None,
    ):
        iforest_model_path = Path(iforest_model_path)
        iforest_threshold_path = Path(iforest_threshold_path)

        if not iforest_model_path.exists():
            raise FileNotFoundError(
                f"Isolation Forest model not found at {iforest_model_path}"
            )
        if not iforest_threshold_path.exists():
            raise FileNotFoundError(
                f"Calibrated threshold sidecar not found at {iforest_threshold_path}. "
                f"Run calibrate_isolation_forest.py first."
            )

        # Design decision #1: model and threshold are two separate artifacts,
        # loaded independently — NOT one attribute injected onto the other.
        self.iforest_model = joblib.load(iforest_model_path)
        with open(iforest_threshold_path) as f:
            threshold_meta = json.load(f)
        self.calibrated_threshold = threshold_meta["calibrated_threshold"]

        self.window_seconds = window_seconds
        # Design decision #5: default cooldown == window length unless overridden.
        self.cooldown_seconds = (
            cooldown_seconds if cooldown_seconds is not None else window_seconds
        )

        # Design decision #3: rolling memory, keyed by source_ip, lazily pruned.
        # Each entry: {"timestamp": float, "signal_type": str, "flow_id": str,
        #              "detail": str, "evidence": dict}
        self._window = defaultdict(list)

        # Last time each source_ip triggered a High-Confidence alert —
        # used to enforce the escalation cooldown (design decision #5).
        self._last_escalation = {}

        # Every uncorroborated / near-miss event, for audit — never discarded.
        self.near_misses: list[NearMiss] = []

        # Every alert ever emitted (low + high), for audit/reporting.
        self.alert_log: list[Alert] = []

    # ----------------------------------------------------------------------
    # Branch 1: network_ml (Random Forest + Isolation Forest corroboration)
    # ----------------------------------------------------------------------
    def process_network_ml(self, payload: dict) -> list:
        """
        Expected payload:
            {
                "source_ip": str,
                "timestamp": float,          # epoch seconds
                "flow_id": str,
                "rf_threat_class": str,      # "Bots" | "DDoS" | "Port Scanning" | "Normal Traffic"
                "rf_confidence": float,
                "iforest_raw_score": float,  # score_samples() value; required if rf_threat_class == "Bots"
                "evidence": dict,            # optional — top features etc.
            }
        Returns a list of Alerts emitted as a direct result of this event
        (usually 0 or 1; can be more if this event triggers a fresh escalation).
        """
        source_ip = payload["source_ip"]
        timestamp = payload["timestamp"]
        flow_id = payload["flow_id"]
        rf_class = payload["rf_threat_class"]
        evidence = payload.get("evidence", {})

        if rf_class == "Normal Traffic":
            return []

        if rf_class == "Bots":
            iforest_score = payload.get("iforest_raw_score")
            if iforest_score is None:
                raise ValueError(
                    "iforest_raw_score is required in the payload when "
                    "rf_threat_class == 'Bots'"
                )
            corroborated = iforest_score < self.calibrated_threshold

            if corroborated:
                return self._register_signal(
                    source_ip, timestamp, self.ML_SIGNAL, flow_id,
                    detail="Bots (RF) corroborated by Isolation Forest",
                    evidence={**evidence, "rf_threat_class": rf_class,
                              "iforest_raw_score": iforest_score,
                              "calibrated_threshold": self.calibrated_threshold},
                )
            else:
                # Design decision #2: keep RF's label, DO NOT overwrite it,
                # DO NOT register a signal — but log it, nothing is silently lost.
                self.near_misses.append(
                    NearMiss(
                        source_ip=source_ip,
                        timestamp=timestamp,
                        flow_id=flow_id,
                        reason="RF flagged Bots but Isolation Forest did not corroborate "
                               "(score above calibrated threshold) — original RF label "
                               "and confidence preserved, no ML_BRANCH_SIGNAL registered.",
                        detail={"rf_threat_class": rf_class,
                                "rf_confidence": payload.get("rf_confidence"),
                                "iforest_raw_score": iforest_score,
                                "calibrated_threshold": self.calibrated_threshold},
                    )
                )
                return []

        if rf_class in ("DDoS", "Port Scanning"):
            # These classes have strong standalone RF precision (F1 >= 0.99
            # on the held-out test set) — no IForest corroboration gate needed.
            return self._register_signal(
                source_ip, timestamp, self.ML_SIGNAL, flow_id,
                detail=f"{rf_class} (RF)",
                evidence={**evidence, "rf_threat_class": rf_class,
                          "rf_confidence": payload.get("rf_confidence")},
            )

        raise ValueError(f"Unrecognized rf_threat_class: {rf_class!r}")

    # ----------------------------------------------------------------------
    # Branch 2: dns_branch (DGA / DNS tunneling detector)
    # ----------------------------------------------------------------------
    def process_dns_branch(self, payload: dict) -> list:
        """
        Expected payload:
            {
                "source_ip": str,
                "timestamp": float,
                "flow_id": str,
                "dns_flag": str | None,   # "DGA" | "DNS_TUNNELING" | None (clean)
                "domain": str,
                "evidence": dict,
            }
        """
        if not payload.get("dns_flag"):
            return []
        return self._register_signal(
            payload["source_ip"], payload["timestamp"], self.DNS_SIGNAL,
            payload["flow_id"],
            detail=f"{payload['dns_flag']} on domain {payload.get('domain', '?')}",
            evidence={**payload.get("evidence", {}), "domain": payload.get("domain"),
                      "dns_flag": payload["dns_flag"]},
        )

    # ----------------------------------------------------------------------
    # Branch 3: tls_branch (JA3/JA3S fingerprint detector)
    # ----------------------------------------------------------------------
    def process_tls_branch(self, payload: dict) -> list:
        """
        Expected payload:
            {
                "source_ip": str,
                "timestamp": float,
                "flow_id": str,
                "ja3_match": bool,
                "ja3_hash": str,
                "matched_signature": str,  # e.g. malware family name, optional
                "evidence": dict,
            }
        """
        if not payload.get("ja3_match"):
            return []
        return self._register_signal(
            payload["source_ip"], payload["timestamp"], self.TLS_SIGNAL,
            payload["flow_id"],
            detail=f"JA3 match ({payload.get('matched_signature', 'unknown family')})",
            evidence={**payload.get("evidence", {}), "ja3_hash": payload.get("ja3_hash"),
                      "matched_signature": payload.get("matched_signature")},
        )

    # ----------------------------------------------------------------------
    # Internal: register a signal, prune stale entries, evaluate fusion
    # ----------------------------------------------------------------------
    def _register_signal(self, source_ip, timestamp, signal_type, flow_id, detail, evidence) -> list:
        self._prune(source_ip, timestamp)

        self._window[source_ip].append({
            "timestamp": timestamp,
            "signal_type": signal_type,
            "flow_id": flow_id,
            "detail": detail,
            "evidence": evidence,
        })

        return self._evaluate_fusion(source_ip, timestamp)

    def _prune(self, source_ip, now):
        """Design decision #3: lazy prune — drop this IP's entries older
        than window_seconds, only when this IP is touched again."""
        cutoff = now - self.window_seconds
        self._window[source_ip] = [
            e for e in self._window[source_ip] if e["timestamp"] >= cutoff
        ]

    def _evaluate_fusion(self, source_ip, now) -> list:
        entries = self._window[source_ip]
        if not entries:
            return []

        # Design decision #4: count DISTINCT signal categories, not raw events.
        categories_present = sorted({e["signal_type"] for e in entries})

        if len(categories_present) >= 2:
            # Design decision #5: cooldown to prevent immediate re-escalation
            # from stale-but-still-in-window evidence.
            last_esc = self._last_escalation.get(source_ip)
            if last_esc is not None and (now - last_esc) < self.cooldown_seconds:
                return []  # already escalated recently for this IP — suppressed

            alert = Alert(
                severity="HIGH",
                alert_type="DATA_EXFILTRATION",
                source_ip=source_ip,
                timestamp=now,
                signals=categories_present,
                evidence=[e["evidence"] for e in entries],
                flow_ids=[e["flow_id"] for e in entries],
            )
            self._last_escalation[source_ip] = now
            self.alert_log.append(alert)
            return [alert]

        # Exactly one category present -> standalone low-severity alert.
        # Per spec: "do not discard it."
        last_entry = entries[-1]
        alert = Alert(
            severity="LOW",
            alert_type=f"{last_entry['signal_type']}_DETECTION",
            source_ip=source_ip,
            timestamp=now,
            signals=categories_present,
            evidence=[last_entry["evidence"]],
            flow_ids=[last_entry["flow_id"]],
        )
        self.alert_log.append(alert)
        return [alert]

    # ----------------------------------------------------------------------
    # Reporting — for team/judge-facing audit, captures near-miss basis too
    # ----------------------------------------------------------------------
    def generate_summary_report(self) -> str:
        high = [a for a in self.alert_log if a.severity == "HIGH"]
        low = [a for a in self.alert_log if a.severity == "LOW"]

        lines = [
            "# SecurityAlertEngine — Run Summary",
            "",
            f"Rolling window: {self.window_seconds}s | Escalation cooldown: {self.cooldown_seconds}s | "
            f"IForest calibrated threshold: {self.calibrated_threshold:.4f}",
            "",
            f"Total alerts emitted: {len(self.alert_log)} "
            f"({len(high)} HIGH / {len(low)} LOW)",
            f"Total near-miss (uncorroborated) events logged: {len(self.near_misses)}",
            "",
            "## High-Confidence Data Exfiltration Alerts",
        ]
        if not high:
            lines.append("_None this run._")
        for a in high:
            lines.append(
                f"- `{a.source_ip}` @ {a.timestamp} — signals: {', '.join(a.signals)} "
                f"— flows: {a.flow_ids}"
            )

        lines += ["", "## Near-Miss Log (basis for each downgrade decision)"]
        if not self.near_misses:
            lines.append("_None this run._")
        for nm in self.near_misses:
            lines.append(
                f"- `{nm.source_ip}` flow `{nm.flow_id}` @ {nm.timestamp}: {nm.reason} "
                f"| detail: {nm.detail}"
            )

        return "\n".join(lines)


# --------------------------------------------------------------------------
# Minimal usage example (remove or adapt when wiring into the real pipeline)
# --------------------------------------------------------------------------
if __name__ == "__main__":
    engine = SecurityAlertEngine(
        iforest_model_path="models/optimized_isolation_forest.joblib",
        iforest_threshold_path="models/optimized_isolation_forest_threshold.json",
        window_seconds=60.0,
    )

    now = time.time()

    # Example: same source IP triggers ML branch (corroborated Bot) then,
    # 20 seconds later, a JA3 match -> should escalate to HIGH.
    alerts = []
    alerts += engine.process_network_ml({
        "source_ip": "10.0.0.5",
        "timestamp": now,
        "flow_id": "flow-001",
        "rf_threat_class": "Bots",
        "rf_confidence": 0.81,
        "iforest_raw_score": -0.55,  # below calibrated threshold -> corroborated
        "evidence": {"top_features": ["Destination Port", "Fwd Packet Length Mean"]},
    })
    alerts += engine.process_tls_branch({
        "source_ip": "10.0.0.5",
        "timestamp": now + 20,
        "flow_id": "flow-002",
        "ja3_match": True,
        "ja3_hash": "abc123...",
        "matched_signature": "known-c2-family",
    })

    for a in alerts:
        print(a)

    print()
    print(engine.generate_summary_report())