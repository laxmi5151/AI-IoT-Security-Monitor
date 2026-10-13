"""Run a deterministic local workflow demo without touching the project database.

This creates one normal synthetic observation and imports one suspicious-rule
fixture into a temporary SQLite database. It sends no packets and scans no device.
"""

from __future__ import annotations

import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_services import (
    add_observation,
    export_incidents_csv,
    export_incidents_pdf,
    gateway_metrics,
    import_gateway_csv,
    list_incidents,
    save_device,
    update_incident,
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ai_iot_demo_") as directory:
        root = Path(directory)
        db_path = root / "demo.sqlite3"
        csv_path = root / "demo_gateway_events.csv"
        save_device("Demo Camera", "Smart Camera", path=db_path,
                    connection_method="Demonstration/simulated")
        add_observation("simulation", "normal traffic",
                        "Synthetic baseline observation; no network packets were sent.", path=db_path)
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "device", "event", "requests_in_window"])
            writer.writerow(["2026-10-13 10:00:00", "Demo Camera", "High request rate", "11"])
        import_gateway_csv(csv_path, db_path)
        incident = list_incidents(source="gateway", limit=1, path=db_path)[0]
        update_incident(incident["incident_id"], "acknowledge",
                        note="Demo review: check whether the burst was expected.", path=db_path)
        metrics = gateway_metrics(db_path)
        print("Local demonstration complete (temporary database removed on exit).")
        print("Normal scenario: one synthetic baseline observation.")
        print("Suspicious scenario: one request-rate rule fixture; anomaly, not confirmed attack.")
        print(f"Gateway incidents: {metrics['incidents']} | unresolved: {metrics['unresolved_incidents']}")
        print(f"CSV report bytes: {len(export_incidents_csv(path=db_path))}")
        print(f"PDF report bytes: {len(export_incidents_pdf(path=db_path))}")


if __name__ == "__main__":
    main()
