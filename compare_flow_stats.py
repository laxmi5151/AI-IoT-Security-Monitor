
from pathlib import Path
import pandas as pd

data_dir = Path("iot_simulator/data/processed")

files = [
    "normal_packet_features.csv",
    "suspicious_packet_features.csv",
]

for filename in files:
    path = data_dir / filename
    df = pd.read_csv(path)

    print("\nFile:", filename)
    print("Rows:", len(df))
    print("\nPacket length statistics:")
    print(df["packet_length_bytes"].describe().round(2))

    print("\nProtocol counts:")
    print(df["protocol"].value_counts().to_string())
