from app.contracts.feature_vector import FeatureVector
from app.contracts.inference_response import InferenceResponse

MODEL_VERSION = "mock-v0"


def classify(fv: FeatureVector) -> InferenceResponse:
    syn_ratio = fv.syn_count / fv.packet_count if fv.packet_count > 0 else 0.0

    if syn_ratio > 0.9 and fv.packets_per_second > 50:
        return InferenceResponse(
            flow_id=fv.flow_id,
            threat_class="SYN_FLOOD",
            confidence=min(0.99, 0.7 + syn_ratio * 0.3),
            anomaly_score=min(0.99, fv.packets_per_second / 500),
            top_features=["syn_count", "packets_per_second"],
            model_version=MODEL_VERSION,
        )

    if fv.unique_dest_ports >= 10 and fv.packet_count <= 5:
        return InferenceResponse(
            flow_id=fv.flow_id,
            threat_class="PORT_SCAN",
            confidence=min(0.99, 0.6 + fv.unique_dest_ports / 100),
            anomaly_score=min(0.99, fv.unique_dest_ports / 50),
            top_features=["unique_dest_ports", "packet_count"],
            model_version=MODEL_VERSION,
        )

    if fv.iat_mean > 1_000_000 and fv.packet_count >= 3:
        periodicity = fv.iat_std / fv.iat_mean if fv.iat_mean > 0 else 1.0
        if periodicity < 0.05:
            return InferenceResponse(
                flow_id=fv.flow_id,
                threat_class="C2_BEACONING",
                confidence=min(0.99, 0.9 - periodicity),
                anomaly_score=min(0.99, 0.9 - periodicity),
                top_features=["iat_std", "iat_mean"],
                model_version=MODEL_VERSION,
            )

    return InferenceResponse(
        flow_id=fv.flow_id,
        threat_class="BENIGN",
        confidence=0.85,
        anomaly_score=0.1,
        top_features=["packet_count"],
        model_version=MODEL_VERSION,
    )