from app.contracts.feature_vector import FeatureVector
from app.contracts.inference_response import InferenceResponse


def traffic_evidence(fv: FeatureVector) -> str:
    return (
        f"{fv.packet_count} packets observed "
        f"({fv.byte_count} bytes total) over {fv.flow_duration / 1_000_000:.2f}s, "
        f"averaging {fv.avg_packet_size:.1f} bytes/packet"
    )


def temporal_evidence(fv: FeatureVector) -> str:
    if fv.packet_count < 2:
        return "single packet observed, no inter-arrival pattern available"

    periodicity = fv.iat_std / fv.iat_mean if fv.iat_mean > 0 else None
    mean_s = fv.iat_mean / 1_000_000
    std_s = fv.iat_std / 1_000_000

    if mean_s < 0.01:
        mean_str = f"{mean_s * 1000:.2f}ms"
        std_str = f"{std_s * 1000:.2f}ms"
    else:
        mean_str = f"{mean_s:.2f}s"
        std_str = f"{std_s:.2f}s"

    if periodicity is not None and periodicity < 0.05:
        return (
            f"mean inter-arrival time = {mean_str}, std = {std_str} "
            f"({periodicity:.1%} of mean) — highly regular, consistent with periodic/automated behavior"
        )
    return f"mean inter-arrival time = {mean_str}, std = {std_str} — variable timing"


def ml_evidence(response: InferenceResponse) -> str:
    top = ", ".join(response.top_features)
    return (
        f"Model classified as {response.threat_class.value} "
        f"(confidence {response.confidence:.0%}, anomaly score {response.anomaly_score:.2f}). "
        f"Top contributing features: {top}"
    )


def rule_evidence(fv: FeatureVector) -> str:
    notes = []
    if fv.unique_dest_ports > 5:
        notes.append(f"source contacted {fv.unique_dest_ports} unique destination ports")
    if fv.syn_count > 0 and fv.packet_count > 0 and fv.syn_count / fv.packet_count > 0.9:
        notes.append(f"{fv.syn_count} of {fv.packet_count} packets were SYN (no completed handshake observed)")
    if fv.unique_destinations > 1:
        notes.append(f"source contacted {fv.unique_destinations} unique destinations in this window")

    if not notes:
        return "no rule-based indicators triggered"
    return "; ".join(notes)


def generate_evidence(fv: FeatureVector, response: InferenceResponse) -> dict:
    return {
        "traffic": traffic_evidence(fv),
        "temporal": temporal_evidence(fv),
        "ml": ml_evidence(response),
        "rule": rule_evidence(fv),
    }