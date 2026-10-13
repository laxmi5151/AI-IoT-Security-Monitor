
from pathlib import Path
import joblib
import pandas as pd

model_path = Path("models/iot_traffic_detector.joblib")
data_dir = Path("iot_simulator/data/processed")

saved = joblib.load(model_path)
model = saved["model"]
features = saved["features"]

for filename, description in [
    ("normal_packet_features.csv", "Normal"),
    ("suspicious_packet_features.csv", "Suspicious"),
]:
    df = pd.read_csv(data_dir / filename)

    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["packet_length_bytes"] = pd.to_numeric(
        df["packet_length_bytes"], errors="coerce"
    )
    df = df.dropna(
        subset=["timestamp", "packet_length_bytes"]
    ).sort_values("timestamp")

    start = df["timestamp"].min()
    df["window"] = (
        (df["timestamp"] - start) // saved["window_seconds"]
    ).astype(int)

    rows = []
    for _, group in df.groupby("window"):
        lengths = group["packet_length_bytes"]
        rows.append({
            "packets_per_second": len(group) / saved["window_seconds"],
            "bytes_per_second": lengths.sum() / saved["window_seconds"],
            "average_packet_size": lengths.mean(),
            "maximum_packet_size": lengths.max(),
            "packet_size_std": lengths.std() if len(group) > 1 else 0,
            "tcp_ratio": group["protocol"].astype(str).str.upper().eq("TCP").mean(),
        })

    X = pd.DataFrame(rows, columns=features)
    predictions = model.predict(X)

    print(f"\n{description} capture:")
    print(f"Windows tested: {len(predictions)}")
    print(f"Predicted Normal: {(predictions == 0).sum()}")
    print(f"Predicted Suspicious: {(predictions == 1).sum()}")
