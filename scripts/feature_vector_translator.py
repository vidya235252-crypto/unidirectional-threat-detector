"""
feature_vector_translator.py

Translates the locked 10-field ML feature vector — the ONLY per-flow
representation the flow engine is confirmed to emit today — into the
payload shape `SecurityAlertEngine.process_behavioral_branch()` expects:
byte_count, flow_duration, pps, dest_ip.

WHY THIS EXISTS
------------------------------------------------------------------------------
process_behavioral_branch() was written assuming byte_count / flow_duration
/ pps / dest_ip arrive as their own named fields, the same way
process_network_ml() receives its 10 named ML features. But the flow
engine has only ever been confirmed to emit the RF/IForest 10-field vector
per flow (Destination Port, Flow Duration, Total Fwd Packets, Total Length
of Fwd Packets, Flow Bytes/s, Fwd Packets/s, Flow IAT Mean, Flow IAT Std,
Fwd Packet Length Mean, Fwd Packet Length Min) — it does not separately
emit those four behavioral-branch fields. Rather than bending the
behavioral detector's contract to match whatever the flow engine happens
to emit (which would just move the mismatch somewhere else), this
translator is the ONE place that maps "what the flow engine actually
gives us" to "what the behavioral branch needs" — so if the live schema
changes again (as it already has once, for Person B's 11-field
extractor), there is exactly one file to update, not every call site.

TWO SILENT-FAILURE RISKS THIS TRANSLATOR EXISTS TO CATCH
------------------------------------------------------------------------------
1. UNIT MISMATCH — Flow Duration, as emitted by CICFlowMeter (the tool
   behind the CICIDS2017-derived training data this pipeline is built
   on), is in MICROSECONDS, not seconds. data_exfilteration_logic.py's
   LOW_AND_SLOW_MIN_DURATION_SECONDS = 3600.0 assumes SECONDS. Fed raw
   microseconds unconverted, a normal 5-second flow (5,000,000 us) would
   look like it lasted 5,000,000 "seconds" and falsely trip low-and-slow
   on nearly every flow — silently miscalibrated, not obviously broken,
   which is worse. This translator divides by 1e6 by default.
   >>> VERIFY this against your actual flow engine's real output before
   >>> trusting it in production. If Person B's live 11-field extractor
   >>> is confirmed to already emit seconds, call this with
   >>> duration_unit="seconds" — don't leave the conversion in "just in
   >>> case", that's the same kind of silent miscalibration in reverse.

2. dest_ip DOES NOT EXIST IN THE FEATURE VECTOR — only Destination PORT
   does. The feature vector was deliberately reduced to numeric ML
   columns; destination IP was never one of them. It has to come from
   the flow record's own metadata — the same place source_ip, timestamp,
   and flow_id already come from for process_network_ml (the flow engine
   necessarily tracks the full 5-tuple to assemble a flow in the first
   place; it just doesn't feed all of it to the model). This translator
   therefore takes flow_meta as a SEPARATE argument from the feature
   vector, and raises loudly if dest_ip is missing rather than silently
   defaulting to "" — a silent default would quietly defeat the
   same-destination low-and-slow enhancement that classify_outbound_
   behavior()'s docstring already reserves dest_ip for.

WHAT byte_count AND pps ARE ACTUALLY MAPPED FROM
------------------------------------------------------------------------------
- byte_count     <- "Total Length of Fwd Packets". This pipeline is
  unidirectional/outbound-only by design, so Fwd IS outbound here — this
  is already exactly "outbound bytes for this flow", no derivation needed.
- pps            <- "Fwd Packets/s" (same reasoning — outbound packet rate).
- flow_duration  <- "Flow Duration", unit-converted per risk #1 above.

If Person B's 11-field live extractor schema is what's actually wired in
(it drops "Total Length of Fwd Packets" and adds "Average Packet Size" /
"Total Backward Packets" / "Flow Packets/s" instead — see the open schema-
reconciliation risk already tracked for the ML branch), this translator
is the file to extend with a second mapping — do NOT patch
process_behavioral_branch itself to understand two schemas.
"""

from __future__ import annotations

from typing import Optional

REQUIRED_FEATURE_KEYS = (
    "Flow Duration",
    "Total Length of Fwd Packets",
    "Fwd Packets/s",
)

REQUIRED_META_KEYS = ("source_ip", "dest_ip", "timestamp", "flow_id")

MICROSECONDS_PER_SECOND = 1_000_000.0


def translate_feature_vector_to_behavioral_payload(
    feature_vector: dict,
    flow_meta: dict,
    *,
    duration_unit: str = "microseconds",
    evidence: Optional[dict] = None,
) -> dict:
    """
    Build the exact payload process_behavioral_branch() expects, from the
    10-field ML feature vector plus the flow record's own metadata.

    Args:
        feature_vector: the same 10-field dict handed to the RF/IForest
            branch for this flow (must contain at least "Flow Duration",
            "Total Length of Fwd Packets", "Fwd Packets/s").
        flow_meta: identifiers the flow engine tracks per flow but does
            NOT feed to the model — must contain "source_ip", "dest_ip",
            "timestamp", "flow_id".
        duration_unit: "microseconds" (default, CICFlowMeter/this
            project's training-data convention) or "seconds". Pass
            explicitly rather than relying on the default once the real
            flow engine's units are confirmed.
        evidence: optional extra context to carry through into the alert.

    Raises:
        KeyError: if a required field is missing from either input — this
            fails loudly at the translation boundary, with the exact
            missing field named, instead of a vague KeyError surfacing
            later from inside process_behavioral_branch.
        ValueError: if duration_unit is not "microseconds" or "seconds".
    """
    missing_features = [k for k in REQUIRED_FEATURE_KEYS if k not in feature_vector]
    if missing_features:
        raise KeyError(
            f"feature_vector is missing required field(s) {missing_features} "
            f"— cannot build a behavioral-branch payload. "
            f"Got keys: {sorted(feature_vector.keys())}"
        )

    missing_meta = [k for k in REQUIRED_META_KEYS if k not in flow_meta]
    if missing_meta:
        raise KeyError(
            f"flow_meta is missing required field(s) {missing_meta}. "
            f"dest_ip in particular is NOT part of the ML feature vector — "
            f"it must come from the flow engine's own flow record, not be "
            f"guessed or defaulted here."
        )

    raw_duration = float(feature_vector["Flow Duration"])
    if duration_unit == "microseconds":
        flow_duration_seconds = raw_duration / MICROSECONDS_PER_SECOND
    elif duration_unit == "seconds":
        flow_duration_seconds = raw_duration
    else:
        raise ValueError(
            f"Unrecognized duration_unit: {duration_unit!r} "
            f"(expected 'microseconds' or 'seconds')"
        )

    return {
        "source_ip": flow_meta["source_ip"],
        "timestamp": flow_meta["timestamp"],
        "flow_id": flow_meta["flow_id"],
        "byte_count": float(feature_vector["Total Length of Fwd Packets"]),
        "flow_duration": flow_duration_seconds,
        "pps": float(feature_vector["Fwd Packets/s"]),
        "dest_ip": flow_meta["dest_ip"],
        "evidence": evidence or {},
    }


# ==============================================================================
# Self-contained demonstration
# ==============================================================================

if __name__ == "__main__":
    # A realistic 10-field vector, duration in RAW MICROSECONDS as CICFlowMeter
    # (and this project's training data) actually represents it — 5,000,000 us
    # = 5 seconds, NOT 5,000,000 seconds.
    sample_vector = {
        "Destination Port": 443,
        "Flow Duration": 5_000_000,
        "Total Fwd Packets": 120,
        "Total Length of Fwd Packets": 48_000,
        "Flow Bytes/s": 9600.0,
        "Fwd Packets/s": 24.0,
        "Flow IAT Mean": 41000.0,
        "Flow IAT Std": 3000.0,
        "Fwd Packet Length Mean": 400.0,
        "Fwd Packet Length Min": 60,
    }
    sample_meta = {
        "source_ip": "10.0.0.15",
        "dest_ip": "93.184.216.34",
        "timestamp": 1_700_000_000.0,
        "flow_id": "flow-demo-001",
    }

    payload = translate_feature_vector_to_behavioral_payload(sample_vector, sample_meta)
    print("Translated payload:", payload)
    assert payload["flow_duration"] == 5.0, "microsecond conversion is broken"
    assert payload["byte_count"] == 48_000
    assert payload["pps"] == 24.0
    assert payload["dest_ip"] == "93.184.216.34"

    # Missing dest_ip must fail LOUDLY, not silently default to "".
    try:
        translate_feature_vector_to_behavioral_payload(
            sample_vector, {"source_ip": "10.0.0.15", "timestamp": 1.0, "flow_id": "f1"}
        )
        raise AssertionError("Expected KeyError for missing dest_ip, none raised")
    except KeyError as e:
        print("Correctly rejected missing dest_ip:", e)

    # duration_unit="seconds" path — for once the real extractor's units
    # are confirmed to already be seconds, not microseconds.
    seconds_vector = dict(sample_vector, **{"Flow Duration": 5.0})
    payload_s = translate_feature_vector_to_behavioral_payload(
        seconds_vector, sample_meta, duration_unit="seconds"
    )
    assert payload_s["flow_duration"] == 5.0

    print("\nAll demonstration assertions passed.")