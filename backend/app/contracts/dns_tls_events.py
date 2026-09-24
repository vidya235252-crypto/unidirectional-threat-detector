import json
from typing import Literal

from pydantic import BaseModel


class DnsQueryRecord(BaseModel):
    domain: str
    query_type: str
    timestamp: str
    src_ip: str

    @classmethod
    def from_json_line(cls, line: str) -> "DnsQueryRecord":
        return cls(**json.loads(line))


class TlsSessionRecord(BaseModel):
    fingerprint: str
    transport: Literal["tls", "quic"]
    role: Literal["client", "server"]
    timestamp: str
    src_ip: str

    @classmethod
    def from_json_line(cls, line: str) -> "TlsSessionRecord":
        return cls(**json.loads(line))
