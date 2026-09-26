import json
import math
import warnings

import joblib
import numpy as np

from app.contracts.feature_vector import FeatureVector
from app.contracts.inference_response import InferenceResponse, ThreatClass
from app.core.config import MODELS_DIR

MODEL_VERSION = "rf-if-v3"

_IF_SIGMOID_SCALE = 0.05

_FEATURE_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Flow Bytes/s", "Fwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Fwd Packet Length Mean",
    "Fwd Packet Length Min",
]

_CLASS_MAP = {
    "Normal Traffic": ThreatClass.BENIGN,
    "Port Scanning": ThreatClass.PORT_SCAN,
    "DDoS": ThreatClass.SYN_FLOOD,
    "Bots": ThreatClass.C2_BEACONING,
}

_rf_model = joblib.load(MODELS_DIR / "random_forest_model.joblib")
_if_model = joblib.load(MODELS_DIR / "optimized_isolation_forest.joblib")

# Cache the two most important RF feature indices once. Reading
# feature_importances_ inside every classify() call walks every tree again.
_TOP_FEATURE_INDICES = _rf_model.feature_importances_.argsort()[::-1][:2]

with open(MODELS_DIR / "optimized_isolation_forest_threshold.json") as _f:
    _IF_THRESHOLD = json.load(_f)["calibrated_threshold"]


def _build_row(fv: FeatureVector) -> np.ndarray:
    return np.array([[
        fv.dst_port,
        fv.flow_duration,
        fv.packet_count,
        fv.byte_count,
        fv.flow_bytes_per_second,
        fv.packets_per_second,
        fv.iat_mean,
        fv.iat_std,
        fv.avg_packet_size,
        fv.fwd_packet_length_min,
    ]])


_IF_LOG1P_INDICES = [1, 2, 3, 4, 5, 6, 7]


def _build_iforest_row(row: np.ndarray) -> np.ndarray:
    """
    Apply the preprocessing used when the Isolation Forest was trained.

    The Random Forest receives the raw feature vector.
    Isolation Forest receives log1p-transformed values for:
      Flow Duration
      Total Fwd Packets
      Total Length of Fwd Packets
      Flow Bytes/s
      Fwd Packets/s
      Flow IAT Mean
      Flow IAT Std
    """
    transformed = row.copy()

    for idx in _IF_LOG1P_INDICES:
        transformed[:, idx] = np.log1p(np.clip(transformed[:, idx], 0, None))

    return transformed


def _normalize_anomaly_score(raw_score: float) -> float:
    x = (_IF_THRESHOLD - raw_score) / _IF_SIGMOID_SCALE
    return 1.0 / (1.0 + math.exp(-x))


def classify(fv: FeatureVector) -> InferenceResponse:
    # SYN-flood guardrail: the trained RF does not consume SYN count, so
    # preserve the PS 26145 flow-level SYN signal as a deterministic rule.
    if (
        fv.protocol.upper() == "TCP"
        and fv.syn_count >= 20
        and fv.packets_per_second >= 100
    ):
        return InferenceResponse(
            flow_id=fv.flow_id,
            threat_class=ThreatClass.SYN_FLOOD,
            confidence=min(0.99, 0.80 + min(fv.syn_count / 1000, 0.19)),
            anomaly_score=min(0.99, 0.80 + min(fv.packets_per_second / 10000, 0.19)),
            top_features=["syn_count", "packets_per_second"],
            model_version=MODEL_VERSION + "+syn-rule",
        )

    if fv.unique_dest_ports >= 10 and fv.packet_count <= 5:
        return InferenceResponse(
            flow_id=fv.flow_id,
            threat_class=ThreatClass.PORT_SCAN,
            confidence=min(0.99, 0.6 + fv.unique_dest_ports / 100),
            anomaly_score=min(0.99, fv.unique_dest_ports / 50),
            top_features=["unique_dest_ports", "packet_count"],
            model_version=MODEL_VERSION,
        )

    row = _build_row(fv)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        # predict() would traverse the full forest and then predict_proba()
        # would traverse it again. The class with the highest probability is
        # exactly the classifier prediction, so keep this to one RF pass.
        rf_proba = _rf_model.predict_proba(row)[0]
        rf_label = _rf_model.classes_[int(np.argmax(rf_proba))]

        if_row = _build_iforest_row(row)
        raw_anomaly = _if_model.score_samples(if_row)[0]

    confidence = float(max(rf_proba))
    anomaly_score = _normalize_anomaly_score(raw_anomaly)

    threat_class = _CLASS_MAP.get(rf_label, ThreatClass.BENIGN)

    # Isolation Forest gates C2/Bots predictions.
    # DDoS and Port Scanning are accepted directly from the RF.
    if rf_label == "Bots" and raw_anomaly > _IF_THRESHOLD:
        threat_class = ThreatClass.BENIGN

    top_features = [_FEATURE_ORDER[i] for i in _TOP_FEATURE_INDICES]

    return InferenceResponse(
        flow_id=fv.flow_id,
        threat_class=threat_class,
        confidence=confidence,
        anomaly_score=anomaly_score,
        top_features=top_features,
        model_version=MODEL_VERSION,
    )
