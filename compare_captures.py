
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "iot_simulator" / "data" / "processed"


def summarize(name):
    path = DATA_DIR / f"{name}_packet_features.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"{name} capture has no packet records.")

    duration = df["timestamp"].max() - df["timestamp"].min()
    if duration <= 0:
        raise ValueError(f"{name} capture has no measurable duration.")

    return {
        "Scenario": name.capitalize(),
        "IPv4 packets": len(df),
        "Duration (seconds)": round(duration, 2),
        "Packets per second": round(len(df) / duration, 2),
    }


def main():
    results = pd.DataFrame([
        summarize("normal"),
        summarize("suspicious"),
    ])

    normal_rate = results.loc[
        results["Scenario"] == "Normal", "Packets per second"
    ].iloc[0]
    suspicious_rate = results.loc[
        results["Scenario"] == "Suspicious", "Packets per second"
    ].iloc[0]

    print("\nCAPTURE COMPARISON")
    print(results.to_string(index=False))
    print(f"\nSuspicious-to-normal packet-rate ratio: {suspicious_rate / normal_rate:.2f}x")
    print("Interpretation: a higher rate indicates unusual traffic volume,")
    print("not proof by itself that the traffic is malicious.")


if __name__ == "__main__":
    main()
