
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

DATA_DIR = Path("iot_simulator/data/processed")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

WINDOW_SECONDS = 2

def extract_windows(filename, label):
    path = DATA_DIR / filename
    df = pd.read_csv(path)

    df["timestamp"] = pd.to_numeric(
        df["timestamp"], errors="coerce"
    )
    df["packet_length_bytes"] = pd.to_numeric(
        df["packet_length_bytes"], errors="coerce"
    )
    df = df.dropna(
        subset=["timestamp", "packet_length_bytes"]
    ).sort_values("timestamp")

    if df.empty:
        raise ValueError(f"No usable packets in {filename}")

    start = df["timestamp"].min()
    df["window"] = (
        (df["timestamp"] - start) // WINDOW_SECONDS
    ).astype(int)

    results = []

    for _, group in df.groupby("window"):
        lengths = group["packet_length_bytes"]
        elapsed = (
            group["timestamp"].max()
            - group["timestamp"].min()
        )

        # Use the fixed window duration for a consistent rate.
        duration = WINDOW_SECONDS

        tcp_ratio = (
            group["protocol"].astype(str).str.upper().eq("TCP").mean()
        )

        results.append({
            "packets_per_second": len(group) / duration,
            "bytes_per_second": lengths.sum() / duration,
            "average_packet_size": lengths.mean(),
            "maximum_packet_size": lengths.max(),
            "packet_size_std": lengths.std() if len(group) > 1 else 0,
            "tcp_ratio": tcp_ratio,
            "label": label,
        })

    return pd.DataFrame(results)


def main():
    normal = extract_windows("normal_packet_features.csv", 0)
    suspicious = extract_windows("suspicious_packet_features.csv", 1)

    data = pd.concat([normal, suspicious], ignore_index=True)

    print("Windows per class:")
    print(data["label"].value_counts().rename(
        index={0: "Normal", 1: "Suspicious"}
    ))
    print("\nFeature preview:")
    print(data.groupby("label").mean(numeric_only=True).round(2))

    X = data.drop(columns=["label"])
    y = data["label"]

    # This is a preliminary demonstration split. Because windows
    # from the same capture are related, the score may be optimistic.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nPreliminary test results:")
    print(classification_report(
        y_test, predictions,
        labels=[0, 1],
        target_names=["Normal", "Suspicious"],
        zero_division=0
    ))
    print("Confusion matrix (actual rows, predicted columns):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    output_path = MODEL_DIR / "iot_traffic_detector.joblib"
    joblib.dump({
        "model": model,
        "features": list(X.columns),
        "window_seconds": WINDOW_SECONDS,
    }, output_path)

    print(f"\nExperimental detector saved to: {output_path}")
    print("This model is a prototype; validate it on separate capture runs.")


if __name__ == "__main__":
    main()
