# preprocessing_utils.py
import numpy as np
import pandas as pd

LOG_TRANSFORM_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Flow Bytes/s", "Fwd Packets/s", "Flow IAT Mean", "Flow IAT Std",
]

def log1p_transform(feature_matrix, feature_cols: list):
    if isinstance(feature_matrix, pd.DataFrame):
        out = feature_matrix.to_numpy(dtype=np.float64).copy()
    else:
        out = feature_matrix.copy()

    col_idx = [feature_cols.index(c) for c in LOG_TRANSFORM_COLS if c in feature_cols]
    out[:, col_idx] = np.log1p(np.clip(out[:, col_idx], a_min=0, a_max=None))

    return out