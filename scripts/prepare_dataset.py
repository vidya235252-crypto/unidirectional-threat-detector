import pandas as pd

INPUT_FILE = "data/raw/combinenew.csv"
OUTPUT_FILE = "data/processed/cicids2017_12_features.csv"

SELECTED_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Count",
    "Average Packet Size",
    "Down/Up Ratio",
    "Label",
]

df = pd.read_csv(INPUT_FILE, usecols=lambda column: column.strip() in SELECTED_COLUMNS)
df.columns = df.columns.str.strip()

df.to_csv(OUTPUT_FILE, index=False)

print(f"Saved {len(df)} rows to {OUTPUT_FILE}")