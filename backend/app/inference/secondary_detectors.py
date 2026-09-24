import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts")
sys.path.insert(0, os.path.abspath(_SCRIPTS_DIR))

from detector_interfaces import classify_dns_query, classify_tls_session  # noqa: E402

from app.contracts.inference_response import InferenceResponse, ThreatClass
from app.core.alert_engine import Alert, compute_severity

DGA_MODEL_VERSION = "dga-tunneling-v1"
JA3_MODEL_VERSION = "ja3-v1"


def classify_dns_record(domain: str, query_type: str, timestamp: str, src_ip: str) -> Optional[Alert]:
    result = classify_dns_query(domain, query_type, timestamp, src_ip)
    if not result["flagged"]:
        return None

    flow_id = f"dns_{uuid.uuid4().hex[:8]}"
    response = InferenceResponse(
        flow_id=flow_id,
        threat_class=ThreatClass.DGA_DNS_TUNNELING,
        confidence=result["confidence"],
        anomaly_score=result["confidence"],
        top_features=[result["reason"]],
        model_version=DGA_MODEL_VERSION,
    )
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        flow_id=flow_id,
        threat_class=response.threat_class.value,
        severity=compute_severity(response),
        confidence=response.confidence,
        anomaly_score=response.anomaly_score,
        evidence={
            "traffic": f"DNS query for {domain} ({query_type}) from {src_ip}",
            "temporal": "",
            "ml": (
                f"DGA/tunneling detector flagged: {result['reason']} "
                f"(entropy={result['entropy_score']:.2f}, ngram={result['ngram_score']:.2f})"
            ),
            "rule": "",
        },
        model_version=DGA_MODEL_VERSION,
    )


def classify_tls_record(
    fingerprint: str, transport: str, role: str, timestamp: str, src_ip: str
) -> Optional[Alert]:
    result = classify_tls_session(fingerprint, transport, role, timestamp, src_ip)
    if not result["flagged"]:
        return None

    flow_id = f"tls_{uuid.uuid4().hex[:8]}"
    response = InferenceResponse(
        flow_id=flow_id,
        threat_class=ThreatClass.MALICIOUS_TLS,
        confidence=result["confidence"],
        anomaly_score=result["confidence"],
        top_features=[result["reason"]],
        model_version=JA3_MODEL_VERSION,
    )
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        flow_id=flow_id,
        threat_class=response.threat_class.value,
        severity=compute_severity(response),
        confidence=response.confidence,
        anomaly_score=response.anomaly_score,
        evidence={
            "traffic": f"{transport.upper()} {role} fingerprint {fingerprint} from {src_ip}",
            "temporal": "",
            "ml": f"JA3/JA3S fingerprint matched known-malicious blocklist entry {result['matched_hash']}",
            "rule": "metadata-only match, no payload decrypted",
        },
        model_version=JA3_MODEL_VERSION,
    )
