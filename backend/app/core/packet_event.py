import json
from datetime import datetime
from typing import Tuple

from pydantic import BaseModel, Field, ValidationError

from app.contracts.feature_vector import Protocol


class PacketEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol
    packet_size: int = Field(ge=0)
    syn_flag: bool = False

    def flow_key(self) -> Tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol.value)

    @classmethod
    def from_json_line(cls, line: str) -> "PacketEvent":
        raw = json.loads(line)
        return cls(**raw)