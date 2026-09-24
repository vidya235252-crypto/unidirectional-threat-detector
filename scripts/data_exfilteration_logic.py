"""
outbound_behavioral_detector.py

Outbound-only behavioral corroboration signal for the unidirectional threat
detector pipeline. Fourth fusion-engine input branch, alongside network_ml,
dns_branch, and tls_branch.

WHAT THIS DETECTS
------------------------------------------------------------------------------
Two independent heuristics, evaluated per streaming flow, merged into ONE
signal category before being handed to SecurityAlertEngine:

    1. Volume baseline drift  — is this entity sending far more outbound
       data than its own recent normal, using a streaming EWMA mean/std
       (no historical flow list is ever stored — O(1) memory per entity).
    2. Low-and-slow           — is this flow a long-lived, low-rate trickle
       to a single destination (classic quiet-exfil shape). Stateless
       threshold check, no history needed.

WHY THEY ARE MERGED INTO ONE CATEGORY, NOT TWO
------------------------------------------------------------------------------
alert_fusion_engine.py escalates to a HIGH DATA_EXFILTRATION alert only when
2+ INDEPENDENT signal categories fire on the same entity in the rolling
window (see design decision #4 in that file: distinct categories count, not
raw event count — this stops one noisy detector from self-escalating).
Baseline-drift and low-and-slow are correlated with each other (a real
exfil flow often trips both at once), so if they were registered as two
separate categories, this branch alone could reach the "2+ signals" bar
with zero ML/DNS/TLS corroboration — defeating the whole point of fusion.
classify_outbound_behavior() therefore reports a single BEHAVIORAL_SIGNAL
event_type: this branch can only ever contribute ONE vote. It corroborates;
it never escalates alone. Both raw sub-results stay in `metrics` for audit.

STREAMING MATH — WHY EWMA, NOT A STORED WINDOW
------------------------------------------------------------------------------
Storing every historical byte count per entity does not scale on
high-throughput links. Instead we keep two running scalars per entity —
an EWMA mean and an EWMA variance — updated in O(1) per flow, using West's
incremental-update form of exponential variance:

    delta      = x - mean
    mean'      = mean + alpha * delta
    variance'  = (1 - alpha) * (variance + alpha * delta^2)

alpha is the smoothing factor (EWMA_ALPHA below); larger alpha reacts
faster to recent flows and "forgets" old behavior faster, smaller alpha is
more stable but slower to adapt to a genuine baseline shift. The Z-score
for the CURRENT flow is always computed against the PRE-update mean/std
(what the entity's baseline looked like walking into this flow), then the
state is updated afterward — otherwise every flow would be partially
scored against itself.

THREAD SAFETY
------------------------------------------------------------------------------
A single threading.RLock guards all state mutation and reads across every
tracked entity. The active asset stream scope here is small and bounded
(a per-window grouping over the feature vector, not open internet-scale
IP space), so a single lock is simple, robust, and carries no meaningful
contention cost at this scale — deliberately chosen over per-entity
locking to avoid the extra bookkeeping (lazy lock creation, double-checked
locking, lock-dict growth) that only pays off at much higher entity
cardinality than this deployment has. Reentrant (RLock, not Lock) so any
future internal method that calls another locking method on the same
thread cannot deadlock itself.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

# ==============================================================================
# Configurable thresholds — tune here, not inline in logic below
# ==============================================================================

EWMA_ALPHA: float = 0.2                # smoothing factor for streaming mean/variance
MIN_FLOWS_FOR_BASELINE: int = 10       # cold-start gate before trusting a Z-score
Z_SCORE_ALERT_THRESHOLD: float = 3.0   # std deviations above rolling mean to alert

LOW_AND_SLOW_MIN_DURATION_SECONDS: float = 3600.0   # 1 hour
LOW_AND_SLOW_MAX_PPS: float = 2.0                   # packets/sec ceiling

MAX_Z_SCORE_SENTINEL: float = 999.0    # clamp ceiling for inf/NaN-producing edge cases

BEHAVIORAL_SIGNAL = "BEHAVIORAL_SIGNAL"


# ==============================================================================
# A. PerIPTracker — streaming, O(1)-memory, thread-safe per-entity state
# ==============================================================================

@dataclass
class _EntityState:
    """Streaming state for one entity. No historical flow list — just the
    running scalars needed to compute an EWMA mean/std incrementally."""

    flow_count: int = 0
    ewma_mean: float = 0.0
    ewma_variance: float = 0.0

    @property
    def ewma_std(self) -> float:
        # variance can be ~0 for a perfectly stable entity; guard the sqrt.
        return math.sqrt(self.ewma_variance) if self.ewma_variance > 0.0 else 0.0


class PerIPTracker:
    """
    Thread-safe streaming tracker of outbound-byte behavior, keyed by
    entity_id — in this deployment, a time-window grouping derived from the
    streaming feature vector (not necessarily a literal source IP; see
    module docstring on naming).

    Locking strategy: ONE threading.RLock guards every read and mutation
    across all entities. Chosen deliberately over per-entity locking: the
    active asset stream scope here is small and bounded, so a single lock
    is simple, easy to reason about, and has no measurable contention cost
    at this scale — it avoids the extra bookkeeping (lazy per-entity lock
    creation, double-checked locking, an ever-growing lock dict) that only
    pays for itself at far higher entity cardinality than this system
    handles. RLock (not Lock) so any internal method that calls another
    locking method on the same thread cannot self-deadlock.
    """

    def __init__(self, alpha: float = EWMA_ALPHA) -> None:
        self._alpha = alpha
        self._states: Dict[str, _EntityState] = {}
        self._lock = threading.RLock()

    def score_and_update(self, entity_id: str, byte_count: float) -> "BaselineResult":
        """
        Compute the Z-score for `byte_count` against this entity's PRE-update
        baseline, then update the streaming mean/variance for next time.
        Cold-start entities (fewer than MIN_FLOWS_FOR_BASELINE prior flows)
        are never scored — they still update state so the baseline builds up.
        The whole read-score-update sequence happens under one lock
        acquisition so no other thread can interleave a state change
        between "read baseline" and "write updated baseline" for the same
        entity.
        """
        with self._lock:
            state = self._states.setdefault(entity_id, _EntityState())

            if state.flow_count < MIN_FLOWS_FOR_BASELINE:
                result = BaselineResult(
                    triggered=False,
                    z_score=0.0,
                    status="INSUFFICIENT_HISTORY",
                )
                self._update_state(state, byte_count)
                return result

            # Score against the baseline as it stood BEFORE this flow.
            std = state.ewma_std
            if std > 0.0:
                z_score = (byte_count - state.ewma_mean) / std
            else:
                # No observed variance yet (e.g. identical byte counts so
                # far) — any deviation at all is meaningful, but we avoid a
                # divide-by-zero spike. Treated as "clearly off baseline"
                # when bytes exceed the flat mean; otherwise 0. Clamped
                # below along with any other inf/NaN edge case.
                z_score = float("inf") if byte_count > state.ewma_mean else 0.0

            z_score = _clamp_finite(z_score)
            triggered = z_score > Z_SCORE_ALERT_THRESHOLD
            result = BaselineResult(
                triggered=triggered,
                z_score=z_score,
                status="SCORED",
            )

            self._update_state(state, byte_count)
            return result

    @staticmethod
    def _update_state(state: _EntityState, byte_count: float, alpha: float = EWMA_ALPHA) -> None:
        """
        West's incremental EWMA mean/variance update. Mutates state in place.

        The very first observation for an entity is seeded directly
        (mean = byte_count, variance = 0.0) rather than run through the
        standard delta formula against an assumed prior mean of 0.0. Without
        this, flow #1 would compute delta = byte_count - 0, injecting a
        large artificial variance from a value that was never actually
        observed — biasing that entity's baseline for many flows afterward
        as it slowly decays out, and making a genuine zero-variance state
        (e.g. an entity sending identical byte counts every flow)
        unreachable in practice.
        """
        if state.flow_count == 0:
            state.ewma_mean = byte_count
            state.ewma_variance = 0.0
            state.flow_count = 1
            return

        delta = byte_count - state.ewma_mean
        state.ewma_mean += alpha * delta
        state.ewma_variance = (1.0 - alpha) * (state.ewma_variance + alpha * delta * delta)
        state.flow_count += 1

    def get_snapshot(self, entity_id: str) -> Optional[dict]:
        """Read-only diagnostic snapshot for an entity, for logging/debugging."""
        with self._lock:
            state = self._states.get(entity_id)
            if state is None:
                return None
            return {
                "entity_id": entity_id,
                "flow_count": state.flow_count,
                "ewma_mean": state.ewma_mean,
                "ewma_std": state.ewma_std,
            }


def _clamp_finite(value: float, sentinel: float = MAX_Z_SCORE_SENTINEL) -> float:
    """
    Intercept any non-finite (inf, -inf, NaN) or out-of-range Z-score before
    it can reach the fixed-contract dict — and downstream JSON logging /
    alert engine serialization, where inf/NaN are not valid JSON and either
    raise or silently corrupt a payload depending on the serializer. NaN is
    treated as "unknown, not necessarily anomalous" and clamped to 0.0
    rather than to the alerting sentinel, since a NaN here means the math
    broke down, not that a genuine deviation was observed.
    """
    if math.isnan(value):
        return 0.0
    if math.isinf(value):
        return sentinel if value > 0 else -sentinel
    if value > sentinel:
        return sentinel
    if value < -sentinel:
        return -sentinel
    return value


@dataclass
class BaselineResult:
    triggered: bool
    z_score: float
    status: str  # "INSUFFICIENT_HISTORY" | "SCORED"


# ==============================================================================
# B. Baseline deviation — thin functional wrapper around PerIPTracker
# ==============================================================================
# (Kept as a tiny function rather than inlining into the wrapper below so it
# has an independent, testable unit boundary — mirrors classify_dns_query /
# classify_tls_session's shape in detector_interfaces.py.)

def check_baseline_drift(tracker: PerIPTracker, entity_id: str, byte_count: float) -> BaselineResult:
    """Score `byte_count` for `entity_id` against its streaming baseline and
    advance that baseline. See PerIPTracker.score_and_update for the math."""
    return tracker.score_and_update(entity_id, byte_count)


# ==============================================================================
# C. Low-and-slow — stateless threshold check
# ==============================================================================

def check_low_and_slow(flow_duration: float, pps: float) -> bool:
    """
    True if this single flow looks like a quiet, sustained trickle: long
    duration AND low packet rate. Stateless — no history, no locking,
    evaluated fresh per flow. Thresholds are the module-level constants
    above; tune those, not this function.
    """
    return flow_duration > LOW_AND_SLOW_MIN_DURATION_SECONDS and pps < LOW_AND_SLOW_MAX_PPS


# ==============================================================================
# D. Fixed-contract wrapper
# ==============================================================================

def classify_outbound_behavior(
    tracker: PerIPTracker,
    ip_address: str,
    timestamp: float,
    byte_count: int,
    flow_duration: float,
    pps: float,
    dest_ip: str,
) -> dict:
    """
    Master entry point for the outbound behavioral branch. Runs both checks
    against the current flow, merges them into a single BEHAVIORAL_SIGNAL
    event so this branch contributes exactly one vote to fusion escalation
    (see module docstring — "why merged, not two categories").

    `dest_ip` is kept as a structured placeholder in this contract on
    purpose: it is accepted but not yet used in scoring, so the signature
    stays aligned with the DNS/TLS branch wrappers' pattern of accepted-but-
    reserved fields (see `query_type` in `classify_dns_query`), and so a
    future same-destination cross-flow rule (e.g. "this entity has sent
    low-and-slow flows to the SAME destination repeatedly") can be added
    without a breaking signature change. Flagged explicitly here rather than
    silently ignored.

    `tracker` is passed in rather than constructed internally so the caller
    owns one long-lived PerIPTracker instance across the whole streaming
    run — constructing a fresh tracker per call would reset every entity's
    baseline to cold-start on every flow.
    """
    baseline_result = check_baseline_drift(tracker, ip_address, float(byte_count))
    low_and_slow_triggered = check_low_and_slow(flow_duration, pps)

    return {
        "event_type": BEHAVIORAL_SIGNAL,
        "entity_id": ip_address,
        "timestamp": timestamp,
        "alert_triggered": bool(baseline_result.triggered or low_and_slow_triggered),
        "metrics": {
            "baseline_drift": {
                "triggered": baseline_result.triggered,
                "z_score": baseline_result.z_score,
                "status": baseline_result.status,
            },
            "low_and_slow": {
                "triggered": low_and_slow_triggered,
                "duration": flow_duration,
                "pps": pps,
            },
        },
    }


# ==============================================================================
# Self-contained demonstration
# ==============================================================================

if __name__ == "__main__":
    tracker = PerIPTracker()
    now = time.time()

    print("=== 1. Cold-start IP (first flow ever seen) ===")
    result = classify_outbound_behavior(
        tracker, "10.0.0.9", now, byte_count=50_000,
        flow_duration=12.0, pps=40.0, dest_ip="8.8.8.8",
    )
    print(result)
    assert result["metrics"]["baseline_drift"]["status"] == "INSUFFICIENT_HISTORY"
    assert result["alert_triggered"] is False

    print("\n=== 2. Normal IP — establish baseline over 10 steady flows, then one more normal flow ===")
    normal_ip = "10.0.0.15"
    for i in range(10):
        classify_outbound_behavior(
            tracker, normal_ip, now + i, byte_count=48_000 + (i * 200),
            flow_duration=15.0, pps=35.0, dest_ip="93.184.216.34",
        )
    result = classify_outbound_behavior(
        tracker, normal_ip, now + 10, byte_count=49_500,
        flow_duration=14.0, pps=36.0, dest_ip="93.184.216.34",
    )
    print(result)
    assert result["metrics"]["baseline_drift"]["status"] == "SCORED"
    assert result["alert_triggered"] is False

    print("\n=== 3. Volume spike — same IP, sudden 40x jump in outbound bytes ===")
    result = classify_outbound_behavior(
        tracker, normal_ip, now + 11, byte_count=2_000_000,
        flow_duration=10.0, pps=30.0, dest_ip="93.184.216.34",
    )
    print(result)
    assert result["metrics"]["baseline_drift"]["triggered"] is True
    assert result["alert_triggered"] is True

    print("\n=== 4. Low-and-slow flow — long duration, low packet rate, fresh IP ===")
    slow_ip = "10.0.0.22"
    # Push this IP past cold-start first with unremarkable flows so this
    # test isolates the low-and-slow path from baseline-drift noise.
    for i in range(10):
        classify_outbound_behavior(
            tracker, slow_ip, now + i, byte_count=10_000,
            flow_duration=5.0, pps=20.0, dest_ip="198.51.100.7",
        )
    result = classify_outbound_behavior(
        tracker, slow_ip, now + 20, byte_count=9_800,
        flow_duration=5000.0, pps=0.8, dest_ip="198.51.100.7",
    )
    print(result)
    assert result["metrics"]["low_and_slow"]["triggered"] is True
    assert result["alert_triggered"] is True

    print("\n=== 5. Zero-variance edge case — identical bytes every flow, then one bigger flow ===")
    flat_ip = "10.0.0.30"
    for i in range(10):
        classify_outbound_behavior(
            tracker, flat_ip, now + i, byte_count=10_000,
            flow_duration=5.0, pps=20.0, dest_ip="198.51.100.7",
        )
    result = classify_outbound_behavior(
        tracker, flat_ip, now + 10, byte_count=10_500,
        flow_duration=5.0, pps=20.0, dest_ip="198.51.100.7",
    )
    print(result)
    # std was 0 going into this flow -> raw z_score would be +inf; must be
    # clamped to the finite sentinel before it ever reaches this dict.
    assert result["metrics"]["baseline_drift"]["z_score"] == MAX_Z_SCORE_SENTINEL
    assert math.isfinite(result["metrics"]["baseline_drift"]["z_score"])
    assert result["alert_triggered"] is True

    print("\nAll demonstration assertions passed.")