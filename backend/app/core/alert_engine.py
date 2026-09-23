import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.contracts.feature_vector import FeatureVector
from app.contracts.inference_response import InferenceResponse
from app.core.evidence import generate_evidence


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    flow_id: str
    threat_class: str
    severity: str
    confidence: float
    anomaly_score: float
    evidence: dict
    model_version: str


def compute_severity(response: InferenceResponse) -> str:
    if response.threat_class.value == "PORT_SCAN":
        return "HIGH"
    if response.confidence >= 0.9:
        return "HIGH"
    if response.confidence >= 0.7:
        return "MEDIUM"
    return "LOW"


class AlertEngine:
    def __init__(self):
        self._alerts: list[Alert] = []

    def process(
        self, fv: FeatureVector, response: InferenceResponse
    ) -> Optional[Alert]:
        if response.threat_class.value == "BENIGN":
            return None

        evidence = generate_evidence(fv, response)
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=response.flow_id,
            threat_class=response.threat_class.value,
            severity=compute_severity(response),
            confidence=response.confidence,
            anomaly_score=response.anomaly_score,
            evidence=evidence,
            model_version=response.model_version,
        )
        self._alerts.append(alert)
        return alert

    def all_alerts(self) -> list[Alert]:
        return list(self._alerts)