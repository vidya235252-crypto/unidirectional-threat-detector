from enum import Enum
from pydantic import BaseModel, Field


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"


class FeatureVector(BaseModel):
    flow_id: str
    timestamp: str
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    flow_duration: float = Field(ge=0)
    packets_per_second: float = Field(ge=0)
    avg_packet_size: float = Field(ge=0)
    iat_mean: float = Field(ge=0)
    iat_std: float = Field(ge=0)
    unique_destinations: int = Field(ge=0)
    unique_dest_ports: int = Field(ge=0)
    protocol: Protocol
    syn_count: int = Field(ge=0)

    model_config = {
        "json_schema_extra": {
            "example": {
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
        }
    }