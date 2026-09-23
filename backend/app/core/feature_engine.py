import statistics
import uuid
from collections import defaultdict
from typing import List

from app.core.flow_engine import Flow
from app.contracts.feature_vector import FeatureVector


class FeatureEngine:
    def __init__(self):
        self._run_prefix = uuid.uuid4().hex[:8]
        self._counter = 0
        self._dest_ip_sets = defaultdict(set)
        self._dest_port_sets = defaultdict(set)

    def _next_flow_id(self) -> str:
        self._counter += 1
        return f"f_{self._run_prefix}_{self._counter:05d}"

    def _inter_arrival_stats(self, flow: Flow) -> tuple[float, float]:
        timestamps = [p.timestamp for p in flow.packets]
        if len(timestamps) < 2:
            return 0.0, 0.0

        deltas_us = [
            (timestamps[i] - timestamps[i - 1]).total_seconds() * 1_000_000
            for i in range(1, len(timestamps))
        ]
        mean = statistics.mean(deltas_us)
        std = statistics.stdev(deltas_us) if len(deltas_us) >= 2 else 0.0
        return mean, std

    def compute_incremental(self, flow: Flow) -> FeatureVector:
        """Streaming variant: updates running per-src_ip cross-flow state with
        this one flow, then extracts using the state as it stands right now.
        Call once per flow, in the order flows close. Unlike compute_batch,
        this never looks ahead at flows that haven't closed yet — matches how
        a real online detector has to work."""
        self._dest_ip_sets[flow.src_ip].add(flow.dst_ip)
        self._dest_port_sets[flow.src_ip].add(flow.dst_port)
        return self._extract_single(
            flow,
            unique_destinations=len(self._dest_ip_sets[flow.src_ip]),
            unique_dest_ports=len(self._dest_port_sets[flow.src_ip]),
        )

    def compute_batch(self, flows: List[Flow]) -> List[FeatureVector]:
        dest_ip_sets = defaultdict(set)
        dest_port_sets = defaultdict(set)

        for flow in flows:
            dest_ip_sets[flow.src_ip].add(flow.dst_ip)
            dest_port_sets[flow.src_ip].add(flow.dst_port)

        vectors = []
        for flow in flows:
            vectors.append(
                self._extract_single(
                    flow,
                    unique_destinations=len(dest_ip_sets[flow.src_ip]),
                    unique_dest_ports=len(dest_port_sets[flow.src_ip]),
                )
            )
        return vectors

    def _extract_single(
        self, flow: Flow, unique_destinations: int, unique_dest_ports: int
    ) -> FeatureVector:
        packet_count = flow.packet_count
        byte_count = sum(p.packet_size for p in flow.packets)
        duration_us = (flow.last_seen - flow.first_seen).total_seconds() * 1_000_000
        duration_seconds = duration_us / 1_000_000

        packets_per_second = packet_count / duration_seconds if duration_seconds > 0 else 0.0
        avg_packet_size = byte_count / packet_count if packet_count > 0 else 0.0
        flow_bytes_per_second = byte_count / duration_seconds if duration_seconds > 0 else 0.0
        iat_mean, iat_std = self._inter_arrival_stats(flow)
        syn_count = sum(1 for p in flow.packets if p.syn_flag)
        fwd_packet_length_min = min((p.packet_size for p in flow.packets), default=0)

        return FeatureVector(
            flow_id=self._next_flow_id(),
            timestamp=flow.last_seen.isoformat(),
            packet_count=packet_count,
            byte_count=byte_count,
            flow_duration=duration_us,
            packets_per_second=packets_per_second,
            avg_packet_size=avg_packet_size,
            iat_mean=iat_mean,
            iat_std=iat_std,
            unique_destinations=unique_destinations,
            unique_dest_ports=unique_dest_ports,
            protocol=flow.protocol,
            syn_count=syn_count,
            dst_port=flow.dst_port,
            flow_bytes_per_second=flow_bytes_per_second,
            fwd_packet_length_min=fwd_packet_length_min,
        )
    