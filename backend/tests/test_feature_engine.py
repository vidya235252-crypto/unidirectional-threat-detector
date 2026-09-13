from datetime import datetime, timezone

from app.core.packet_event import PacketEvent
from app.core.flow_engine import FlowEngine
from app.core.feature_engine import FeatureEngine


def make_packet(ts, src_ip, dst_ip, src_port, dst_port, size, syn=False):
    return PacketEvent(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        packet_size=size,
        syn_flag=syn,
    )


def test_single_flow_known_values():
    base = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)
    packets = [
        make_packet(base, "10.0.0.1", "10.0.0.2", 5000, 80, 100, syn=True),
        make_packet(base.replace(second=1), "10.0.0.1", "10.0.0.2", 5000, 80, 200),
        make_packet(base.replace(second=2), "10.0.0.1", "10.0.0.2", 5000, 80, 300),
    ]

    flow_engine = FlowEngine()
    for p in packets:
        flow_engine.process_packet(p)
    flows = flow_engine.flush_all()

    feature_engine = FeatureEngine()
    vectors = feature_engine.compute_batch(flows)

    assert len(vectors) == 1
    v = vectors[0]

    assert v.packet_count == 3
    assert v.byte_count == 600
    assert v.avg_packet_size == 200.0
    assert v.flow_duration == 2_000_000.0
    assert v.packets_per_second == 1.5
    assert v.iat_mean == 1_000_000.0
    assert v.iat_std == 0.0
    assert v.syn_count == 1
    assert v.unique_destinations == 1
    assert v.unique_dest_ports == 1
    assert v.protocol == "TCP"


def test_single_packet_flow_has_zero_duration_and_rate():
    base = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)
    packet = make_packet(base, "10.0.0.1", "10.0.0.2", 5000, 80, 60, syn=True)

    flow_engine = FlowEngine()
    flow_engine.process_packet(packet)
    flows = flow_engine.flush_all()

    feature_engine = FeatureEngine()
    vectors = feature_engine.compute_batch(flows)

    v = vectors[0]
    assert v.packet_count == 1
    assert v.flow_duration == 0.0
    assert v.packets_per_second == 0.0
    assert v.iat_mean == 0.0
    assert v.iat_std == 0.0


def test_unique_destinations_computed_across_flows_not_within():
    base = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)
    packets = [
        make_packet(base, "10.0.0.9", "10.0.0.1", 4000, 1, 60, syn=True),
        make_packet(base, "10.0.0.9", "10.0.0.1", 4000, 2, 60, syn=True),
        make_packet(base, "10.0.0.9", "10.0.0.5", 4000, 1, 60, syn=True),
    ]

    flow_engine = FlowEngine()
    for p in packets:
        flow_engine.process_packet(p)
    flows = flow_engine.flush_all()

    feature_engine = FeatureEngine()
    vectors = feature_engine.compute_batch(flows)

    assert len(vectors) == 3
    for v in vectors:
        assert v.unique_destinations == 2
        assert v.unique_dest_ports == 2


def test_reverse_traffic_creates_separate_flow_not_merged():
    base = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)
    forward = make_packet(base, "10.0.0.1", "10.0.0.2", 5000, 80, 100, syn=True)
    reverse = make_packet(base.replace(second=1), "10.0.0.2", "10.0.0.1", 80, 5000, 100)

    flow_engine = FlowEngine()
    flow_engine.process_packet(forward)
    flow_engine.process_packet(reverse)

    assert flow_engine.flow_count() == 2
    assert forward.flow_key() != reverse.flow_key()