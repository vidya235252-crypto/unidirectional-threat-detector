from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple

from app.core.packet_event import PacketEvent

FlowKey = Tuple[str, str, int, int, str]


@dataclass
class Flow:
    flow_key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packets: List[PacketEvent] = field(default_factory=list)

    def add_packet(self, packet: PacketEvent) -> None:
        self.packets.append(packet)
        if packet.timestamp < self.first_seen:
            self.first_seen = packet.timestamp
        if packet.timestamp > self.last_seen:
            self.last_seen = packet.timestamp

    def is_stale(self, current_time: datetime, window_seconds: float) -> bool:
        elapsed = (current_time - self.last_seen).total_seconds()
        return elapsed > window_seconds

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def src_ip(self) -> str:
        return self.flow_key[0]

    @property
    def dst_ip(self) -> str:
        return self.flow_key[1]

    @property
    def src_port(self) -> int:
        return self.flow_key[2]

    @property
    def dst_port(self) -> int:
        return self.flow_key[3]

    @property
    def protocol(self) -> str:
        return self.flow_key[4]


class FlowEngine:
    def __init__(self):
        self.flows: Dict[FlowKey, Flow] = {}

    def process_packet(self, packet: PacketEvent) -> Flow:
        key = packet.flow_key()

        if key not in self.flows:
            self.flows[key] = Flow(
                flow_key=key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )

        flow = self.flows[key]
        flow.add_packet(packet)
        return flow

    def get_stale_flows(self, current_time: datetime, window_seconds: float) -> List[Flow]:
        stale = [
            flow for flow in self.flows.values()
            if flow.is_stale(current_time, window_seconds)
        ]
        for flow in stale:
            del self.flows[flow.flow_key]
        return stale

    def flush_all(self) -> List[Flow]:
        remaining = list(self.flows.values())
        self.flows.clear()
        return remaining


    def get_flow(self, flow_key: FlowKey) -> Flow:
        return self.flows[flow_key]

    def all_flows(self) -> List[Flow]:
        return list(self.flows.values())

    def flow_count(self) -> int:
        return len(self.flows)