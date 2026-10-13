
from scapy.all import rdpcap, IP, TCP, UDP
from pathlib import Path
import csv
import sys

# Locate project folders
PROJECT_DIR = Path(__file__).resolve().parents[2]
CAPTURE_DIR = PROJECT_DIR / "captures"
OUTPUT_DIR = PROJECT_DIR / "iot_simulator" / "data" / "processed"


def extract_features(capture_name):
    # Only allow capture filenames, not arbitrary paths
    allowed_captures = {
        "normal": "iot_traffic_normal.pcapng",
        "suspicious": "suspicious_traffic.pcapng",
    }

    if capture_name not in allowed_captures:
        print("Usage: python iot_simulator/network/feature_extraction.py normal")
        print("   or: python iot_simulator/network/feature_extraction.py suspicious")
        return

    capture_file = CAPTURE_DIR / allowed_captures[capture_name]
    output_file = OUTPUT_DIR / f"{capture_name}_packet_features.csv"

    if not capture_file.exists():
        print(f"Capture file not found: {capture_file}")
        return

    print(f"Reading {capture_name} Wireshark capture...")
    packets = rdpcap(str(capture_file))
    rows = []

    for packet in packets:
        if IP not in packet:
            continue

        ip_layer = packet[IP]
        source_port = ""
        destination_port = ""
        protocol = "Other"

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        rows.append({
            "timestamp": float(packet.time),
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_length_bytes": len(packet),
        })

    if not rows:
        print("No IPv4 packets were found in the capture.")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Packets processed: {len(packets)}")
    print(f"IPv4 packet features extracted: {len(rows)}")
    print(f"CSV saved to: {output_file}")


if __name__ == "__main__":
    selected_capture = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    extract_features(selected_capture)
