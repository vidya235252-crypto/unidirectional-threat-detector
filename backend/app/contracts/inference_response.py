from enum import Enum
from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    BENIGN = "BENIGN"
    C2_BEACONING = "C2_BEACONING"
    PORT_SCAN = "PORT_SCAN"
    SYN_FLOOD = "SYN_FLOOD"
    DGA_DNS_TUNNELING = "DGA_DNS_TUNNELING"
    MALICIOUS_TLS = "MALICIOUS_TLS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


class InferenceResponse(BaseModel):
    flow_id: str
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=1)
    anomaly_score: float = Field(ge=0, le=1)
    top_features: list[str]
    model_version: str

    model_config = {
        "protected_namespaces": (),
        "json_schema_extra": {
            "example": {
                "flow_id": "f_10293",
                "threat_class": "C2_BEACONING",
                "confidence": 0.96,
                "anomaly_score": 0.91,
                "top_features": ["iat_std", "unique_destinations"],
                "model_version": "v1"
            }
        }
    }