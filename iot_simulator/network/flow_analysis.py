
import pandas as pd
from pathlib import Path
import sys

PROJECT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_DIR / "iot_simulator" / "data" / "processed"


def analyze_flows(capture_name):
    if capture_name not in {"normal", "suspicious"}:
        print("Usage:")
        print("python iot_simulator/network/flow_analysis.py normal")
        print("python iot_simulator/network/flow_analysis.py suspicious")
        return

    input_file = DATA_DIR / f"{capture_name}_packet_features.csv"
    output_file = DATA_DIR / f"{capture_name}_flow_features.csv"

    if not input_file.exists():
        print(f"Input CSV not found: {input_file}")
        print("Run feature_extraction.py for this capture first.")
        return

    df = pd.read_csv(input_file)

    if df.empty:
        print("The packet dataset is empty.")
        return

    # Group packets into 10-second windows and network flows
    df["time_window"] = (df["timestamp"] // 10).astype(int) * 10

    flows = (
        df.groupby(
            [
                "time_window",
                "source_ip",
                "destination_ip",
                "protocol",
                "source_port",
                "destination_port",
            ],
            dropna=False,
        )
        .agg(
            packet_count=("packet_length_bytes", "count"),
            total_bytes=("packet_length_bytes", "sum"),
            average_packet_size=("packet_length_bytes", "mean"),
            first_packet_time=("timestamp", "min"),
            last_packet_time=("timestamp", "max"),
        )
        .reset_index()
    )

    flows["duration_seconds"] = (
        flows["last_packet_time"] - flows["first_packet_time"]
    )

    flows["packets_per_second"] = (
        flows["packet_count"] / flows["duration_seconds"].clip(lower=1)
    )

    flows["bytes_per_second"] = (
        flows["total_bytes"] / flows["duration_seconds"].clip(lower=1)
    )

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    flows.to_csv(output_file, index=False)

    print(f"\n--- {capture_name.upper()} FLOW ANALYSIS ---")
    print(f"Input packets: {len(df)}")
    print(f"Flow records created: {len(flows)}")
    print(f"Output saved to: {output_file}")
    print("\nFirst five flow records:")
    print(flows.head().to_string(index=False))


if __name__ == "__main__":
    selected_capture = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    analyze_flows(selected_capture)
