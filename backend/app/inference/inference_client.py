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


def _normalize_anomaly_score(raw_score: float) -> float:
    x = (_IF_THRESHOLD - raw_score) / _IF_SIGMOID_SCALE
    return 1.0 / (1.0 + math.exp(-x))


def classify(fv: FeatureVector) -> InferenceResponse:
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
        rf_label = _rf_model.predict(row)[0]
        rf_proba = _rf_model.predict_proba(row)[0]
        raw_anomaly = _if_model.score_samples(row)[0]

    confidence = float(max(rf_proba))
    anomaly_score = _normalize_anomaly_score(raw_anomaly)

    threat_class = _CLASS_MAP.get(rf_label, ThreatClass.BENIGN)

    top_idx = _rf_model.feature_importances_.argsort()[::-1][:2]
    top_features = [_FEATURE_ORDER[i] for i in top_idx]

    return InferenceResponse(
        flow_id=fv.flow_id,
        threat_class=threat_class,
        confidence=confidence,
        anomaly_score=anomaly_score,
        top_features=top_features,
        model_version=MODEL_VERSION,
    )
