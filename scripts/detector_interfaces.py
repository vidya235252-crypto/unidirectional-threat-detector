"""
detector_interfaces.py

Fixed-contract wrapper functions around the existing DGA/DNS-tunneling and
JA3 fingerprint detectors, so a teammate can import two stable function
signatures without touching calibration internals or file paths.

    classify_dns_query(domain, query_type, timestamp, src_ip) -> dict
    classify_tls_session(fingerprint, transport, role, timestamp, src_ip) -> dict

Drop this file in scripts/, alongside dga_dns_tunneling_detector.py and
ja3_detector.py — it imports functions/constants directly from both rather
than reimplementing anything.

================================================================================
DESIGN NOTES
================================================================================
1. Calibration happens ONCE, lazily, on first call — not per call.
   dga_dns_tunneling_detector.py's own main() calibrates entropy_threshold
   and ngram_threshold from Bambenek + Tranco each run, and its closing
   line says to "hardcode the thresholds ... for production use." Rather
   than pasting in numbers that go stale the next time calibration is
   rerun, this module reruns the SAME calibration functions once, on the
   first call, and caches the result at module level (`_dga_state`).
   Every call after that is pure lookup/scoring — no repeated file I/O.

2. DNS tunneling is inherently a MULTI-QUERY pattern (rolling query rate +
   subdomain length), but the fixed contract classifies ONE query at a
   time. The original detect_tunneling() is batch/DataFrame-based — it
   rolls over a whole log at once. This wrapper reimplements the same two
   checks (high_query_rate, long_subdomain) as STREAMING, stateful logic:
   a small per-src_ip rolling window (module-level, same pattern used in
   SecurityAlertEngine's per-source_ip window) updates on every call.
   Same defaults as the original: window_seconds=5, query_count_threshold=20,
   subdomain_len_threshold=30.

3. `query_type` is accepted (it's part of the fixed contract) but NOT
   currently used in scoring — the underlying detector has no
   query-type-aware logic today (e.g. treating TXT records, a common
   tunneling vector, differently from A records). Flagged here explicitly
   rather than silently ignored: if type-aware scoring is wanted later,
   that's new logic to add, not something already happening quietly.

4. Field naming mismatch, worth resolving before wiring into the Alert
   Engine: this contract uses `src_ip`; alert_fusion_engine.py and the
   RF/IForest branch use `source_ip`. Pick one name project-wide, or add
   an explicit rename step at the integration boundary.

5. classify_tls_session takes an ALREADY-COMPUTED fingerprint string, not
   raw ClientHello/ServerHello fields. ja3_detector.py's analyze_session()
   computes the JA3/JA3S hash from raw handshake fields (cipher suites,
   extensions, etc.) — that computation step lives upstream of this
   function (wherever the handshake is parsed) and isn't duplicated here,
   since the fixed contract already hands us a hash.
================================================================================
"""

import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Ensure this file's directory is importable regardless of caller's cwd,
# so the two sibling detector modules resolve cleanly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dga_dns_tunneling_detector import (  # noqa: E402
    load_bambenek, load_tranco, build_ngram_model, calibrate_threshold,
    compute_entropy, ngram_score, is_dga, build_allowlist,
    BAMBENEK_PATH, TRANCO_PATH, ALLOWLIST_SIZE, ENTROPY_BENIGN_WEIGHT,
)
from ja3_detector import (  # noqa: E402
    load_fingerprint_blocklist, JA3_HASH_PATTERN, BLOCKLIST_PATH,
)

# --------------------------------------------------------------------------
# DGA / DNS tunneling
# --------------------------------------------------------------------------
_dga_state = None  # populated lazily on first classify_dns_query() call

# Streaming rolling window for tunneling checks, keyed by src_ip.
# Each entry: (timestamp: datetime, domain: str)
_dns_window = defaultdict(list)

DNS_WINDOW_SECONDS = 5
DNS_QUERY_COUNT_THRESHOLD = 20
DNS_SUBDOMAIN_LEN_THRESHOLD = 30


def _get_dga_state():
    global _dga_state
    if _dga_state is not None:
        return _dga_state

    malicious_domains = load_bambenek(BAMBENEK_PATH)
    benign_domains = load_tranco(TRANCO_PATH)
    ngram_model = build_ngram_model(benign_domains)

    mal_entropy = [compute_entropy(d) for d in malicious_domains]
    ben_entropy = [compute_entropy(d) for d in benign_domains]
    mal_ngram = [ngram_score(d, ngram_model) for d in malicious_domains]
    ben_ngram = [ngram_score(d, ngram_model) for d in benign_domains]

    entropy_threshold, _ = calibrate_threshold(
        mal_entropy, ben_entropy, higher_is_malicious=True,
        benign_weight=ENTROPY_BENIGN_WEIGHT)
    ngram_threshold, _ = calibrate_threshold(
        mal_ngram, ben_ngram, higher_is_malicious=False)

    _dga_state = {
        "bambenek_set": malicious_domains,
        "ngram_model": ngram_model,
        "entropy_threshold": entropy_threshold,
        "ngram_threshold": ngram_threshold,
        "allowlist_set": build_allowlist(benign_domains, ALLOWLIST_SIZE),
    }
    return _dga_state


def _longest_subdomain_label(domain: str) -> int:
    if not domain or "." not in domain:
        return 0
    labels = domain.split(".")
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    return max((len(lbl) for lbl in subdomain_labels), default=0)


def _check_tunneling(domain: str, timestamp: datetime, src_ip: str) -> dict:
    """Streaming equivalent of detect_tunneling()'s two checks, evaluated
    for a single incoming query against a rolling per-src_ip window."""
    cutoff = timestamp - timedelta(seconds=DNS_WINDOW_SECONDS)
    window = [(t, d) for (t, d) in _dns_window[src_ip] if t >= cutoff]
    window.append((timestamp, domain))
    _dns_window[src_ip] = window

    return {
        "high_query_rate": len(window) >= DNS_QUERY_COUNT_THRESHOLD,
        "long_subdomain": _longest_subdomain_label(domain) >= DNS_SUBDOMAIN_LEN_THRESHOLD,
    }


def classify_dns_query(domain: str, query_type: str, timestamp: str, src_ip: str) -> dict:
    """
    Fixed contract:
        {"flagged": bool, "reason": str, "confidence": float,
         "entropy_score": float, "ngram_score": float}
    """
    state = _get_dga_state()

    try:
        ts = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        ts = datetime.utcnow()  # never let a malformed timestamp crash the call

    dga_result = is_dga(
        domain, state["bambenek_set"], state["ngram_model"],
        state["entropy_threshold"], state["ngram_threshold"], state["allowlist_set"],
    )
    tunneling = _check_tunneling((domain or "").strip().lower(), ts, src_ip)

    reasons, confidences = [], []
    if dga_result["flagged"]:
        reasons.append(dga_result["reason"])
        confidences.append(dga_result["confidence"])
    if tunneling["high_query_rate"] and tunneling["long_subdomain"]:
        reasons.append("high_query_rate+long_subdomain")
        confidences.append(0.95)
    elif tunneling["high_query_rate"]:
        reasons.append("high_query_rate")
        confidences.append(0.8)
    elif tunneling["long_subdomain"]:
        reasons.append("long_subdomain")
        confidences.append(0.7)

    if not reasons:
        reasons.append(dga_result["reason"] or "clean")  # e.g. "allowlisted", "invalid_domain"

    return {
        "flagged": bool(dga_result["flagged"] or tunneling["high_query_rate"] or tunneling["long_subdomain"]),
        "reason": "+".join(reasons),
        "confidence": max(confidences) if confidences else 0.0,
        "entropy_score": dga_result["entropy"] if dga_result["entropy"] is not None else 0.0,
        "ngram_score": dga_result["ngram_score"] if dga_result["ngram_score"] is not None else 0.0,
    }


# --------------------------------------------------------------------------
# JA3 / JA3S
# --------------------------------------------------------------------------
_ja3_blocklist = None


def _get_ja3_blocklist():
    global _ja3_blocklist
    if _ja3_blocklist is None:
        _ja3_blocklist = load_fingerprint_blocklist(BLOCKLIST_PATH)
    return _ja3_blocklist


def classify_tls_session(fingerprint: str, transport: str, role: str, timestamp: str, src_ip: str) -> dict:
    """
    Fixed contract:
        {"flagged": bool, "reason": str, "confidence": float,
         "matched_hash": str | None}
    """
    if transport not in ("tls", "quic"):
        return {"flagged": False, "reason": "invalid_transport", "confidence": 0.0, "matched_hash": None}
    if role not in ("client", "server"):
        return {"flagged": False, "reason": "invalid_role", "confidence": 0.0, "matched_hash": None}

    fp = (fingerprint or "").strip().lower()
    if not JA3_HASH_PATTERN.fullmatch(fp):
        return {"flagged": False, "reason": "invalid_fingerprint_format", "confidence": 0.0, "matched_hash": None}

    blocklist = _get_ja3_blocklist()
    if fp in blocklist:
        return {"flagged": True, "reason": "blocklist_match", "confidence": 1.0, "matched_hash": fp}
    return {"flagged": False, "reason": "clean", "confidence": 0.0, "matched_hash": None}
