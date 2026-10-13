import tempfile
import unittest
from pathlib import Path
import csv
import os
from unittest.mock import patch

import pandas as pd

from security_services import (
    DEVICE_CATEGORIES, add_observation, app_context, assistant_reply, create_alert,
    count_incidents, export_alerts_csv, export_incidents_csv, export_incidents_pdf,
    gateway_metrics, get_alert, incident_audit, init_db, list_alerts, list_devices,
    list_incidents, model_feature_names, predict_flows, read_model_csv, remove_device,
    save_device, update_alert, update_device_status, update_incident, validate_model_frame,
    import_gateway_csv, flow_compatibility_report, safe_predict_flows,
    gemini_config_status, test_gemini_connection,
)


class SecurityServicesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_persistent_device_and_alert_lifecycle(self):
        device_id = save_device("Test Camera", DEVICE_CATEGORIES[0], "Lab", path=self.db)
        self.assertEqual(list_devices(self.db)[0]["id"], device_id)
        alert_id = create_alert("Test Camera", "simulation", "request-rate rule", "burst observed",
                                "Medium", "11 requests in 2 seconds", "Rate exceeded demo threshold",
                                "Check whether this activity was expected", path=self.db)
        self.assertEqual(get_alert(alert_id, self.db)["device_id"], device_id)
        update_alert(alert_id, acknowledged=True, annotation="Reviewed", path=self.db)
        self.assertEqual(get_alert(alert_id, self.db)["annotation"], "Reviewed")
        self.assertTrue(remove_device(device_id, self.db))
        self.assertIsNone(get_alert(alert_id, self.db)["device_id"])
        self.assertEqual(len(list_alerts(path=self.db)), 1)

    def test_simulated_event_review_assistant_report_round_trip(self):
        save_device("Camera demo", "Smart Camera", path=self.db)
        add_observation("simulation", "traffic", "normal synthetic request", path=self.db)
        alert_id = create_alert("Camera demo", "simulation", "request-rate rule", "frequency exceeded",
                                "Medium", "11 requests in 2 seconds", "The demo threshold was crossed",
                                "Verify whether the burst was expected", path=self.db)
        context = {"recent_alerts": list_alerts(path=self.db), "devices": list_devices(self.db)}
        reply, _ = assistant_reply("Explain my latest alert", context, api_key=None)
        self.assertIn(alert_id, " ".join(a["id"] for a in context["recent_alerts"]))
        self.assertIn("Camera demo", reply)
        update_alert(alert_id, acknowledged=True, resolved=True, path=self.db)
        self.assertIn(b"Camera demo", export_alerts_csv(self.db))
        self.assertTrue(get_alert(alert_id, self.db)["resolved"])

    def test_registration_validates_fields(self):
        for values in [("", DEVICE_CATEGORIES[0]), ("Valid", "Unknown")]:
            with self.assertRaises(ValueError):
                save_device(*values, path=self.db)

    def test_monitoring_status_requires_actual_evidence(self):
        device_id = save_device("Unverified", "Router", path=self.db)
        self.assertEqual(list_devices(self.db)[0]["monitoring_status"], "Registered")
        with self.assertRaisesRegex(ValueError, "successful connection test"):
            update_device_status(device_id, "Reachable", path=self.db)
        with self.assertRaisesRegex(ValueError, "verified traffic source"):
            update_device_status(device_id, "Monitored", path=self.db)

    def test_gateway_csv_preserves_raw_rows_deduplicates_detections_and_clusters_incidents(self):
        source = Path(self.temp.name) / "security_events.csv"
        with source.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "device", "event", "requests_in_window"])
            writer.writerow(["2026-10-13 10:00:00", "Camera-01", "High request rate", "11"])
            writer.writerow(["2026-10-13 10:00:00", "Camera-01", "High request rate", "11"])
            writer.writerow(["2026-10-13 10:01:00", "Camera-01", "High request rate", "12"])
            writer.writerow(["2026-10-13 10:20:00", "Camera-01", "High request rate", "11"])
        self.assertEqual(import_gateway_csv(source, self.db)["raw_imported"], 4)
        stats = gateway_metrics(self.db)
        self.assertEqual(stats["raw_events"], 4)
        self.assertEqual(stats["unique_detections"], 3)
        self.assertEqual(stats["incidents"], 2)
        self.assertEqual(stats["unresolved_incidents"], 2)
        self.assertEqual(import_gateway_csv(source, self.db)["raw_imported"], 0)
        grouped = list_incidents(source="gateway", limit=10, path=self.db)
        repeated = max(grouped, key=lambda row: row["occurrence_count"])
        self.assertEqual(repeated["occurrence_count"], 2)
        self.assertEqual(repeated["raw_occurrence_count"], 3)
        self.assertTrue(repeated["first_seen"].endswith("+00:00"))
        create_alert("Demo", "simulation", "synthetic", "demo event", "Low", "demo",
                     "demo", "review", path=self.db)
        self.assertEqual(gateway_metrics(self.db)["incidents"], 2)

    def test_incident_status_audit_filters_and_csv_pdf_exports(self):
        incident_id = create_alert("Report device", "simulation", "rule", "unusual rate", "Low",
                                   "controlled evidence", "possible anomaly", "review traffic", path=self.db)
        self.assertEqual(count_incidents(status="Open", path=self.db), 1)
        self.assertTrue(update_incident(incident_id, "investigate", note="checking", path=self.db))
        self.assertTrue(update_incident(incident_id, "resolve", path=self.db))
        self.assertTrue(update_incident(incident_id, "reopen", path=self.db))
        self.assertEqual(list_incidents(search="Report device", path=self.db)[0]["status"], "Open")
        self.assertEqual(len(incident_audit(incident_id, self.db)), 4)
        self.assertIn(b"Report device", export_incidents_csv(path=self.db))
        self.assertTrue(export_incidents_pdf(path=self.db).startswith(b"%PDF-1.4"))
        self.assertIn(b"No incidents matched", export_incidents_pdf(status="Resolved", path=self.db))

    def test_feature_schema_and_order_are_strict(self):
        names = model_feature_names()
        frame = pd.DataFrame([[0.0] * len(names)], columns=list(reversed(names)))
        checked = validate_model_frame(frame)
        self.assertEqual(list(checked.columns), names)
        with self.assertRaisesRegex(ValueError, "missing required"):
            validate_model_frame(frame.drop(columns=[names[0]]))
        bad = frame.copy()
        bad[names[0]] = float("inf")
        with self.assertRaisesRegex(ValueError, "infinite"):
            validate_model_frame(bad)
        sentinel = frame.copy()
        sentinel["Init_Win_bytes_forward"] = -1
        self.assertEqual(validate_model_frame(sentinel)["Init_Win_bytes_forward"].iloc[0], -1)

    def test_existing_model_prediction_on_valid_schema(self):
        names = model_feature_names()
        result = predict_flows(pd.DataFrame([[0.0] * len(names)], columns=names))
        self.assertIn(result["rows"][0]["prediction"], {"BENIGN", "ATTACK"})
        self.assertTrue(result["model_version"].startswith("random_forest_ids:"))
        self.assertIsNotNone(result["rows"][0]["probabilities"])

    def test_assistant_fallback_uses_actual_context_without_provider(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            reply, provider = assistant_reply("Explain my latest alert", {
                "recent_alerts": [{"severity": "High", "device_name": "Test Camera",
                                   "timestamp": "2026-10-13T10:00:00Z", "method": "request-rate rule",
                                   "behavior": "burst observed", "evidence": "11 requests",
                                   "recommendation": "review it"}], "devices": [],
            }, api_key=None)
        self.assertEqual(provider, "local help fallback (Gemini is not configured)")
        self.assertIn("Test Camera", reply)
        self.assertIn("11 requests", reply)

    def test_model_csv_rejects_unrelated_network_summary(self):
        class Upload:
            def getvalue(self):
                return b"packet_count,total_bytes\n3,40\n"
        with self.assertRaisesRegex(ValueError, "missing required model features"):
            read_model_csv(Upload())

    def test_safe_inference_records_validation_failures(self):
        result = safe_predict_flows(pd.DataFrame({"packet_count": [4]}), self.db)
        self.assertFalse(result["ok"])
        self.assertIn("missing required model features", result["error"])
        from security_services import list_observations
        self.assertEqual(list_observations(path=self.db)[0]["kind"], "inference error")

    def test_saved_iot_flow_schema_is_not_silently_mapped_to_cicids(self):
        flow_path = Path(__file__).resolve().parents[1] / "iot_simulator" / "data" / "processed" / "iot_flow_features.csv"
        if not flow_path.exists():
            self.skipTest("Bundled IoT flow feature CSV is unavailable")
        report = flow_compatibility_report(pd.read_csv(flow_path, nrows=5))
        self.assertEqual(report["exact_features_present"], 0)
        self.assertGreater(report["reliable_model_features_missing"], 0)

    def test_missing_gateway_source_and_new_database_recover_cleanly(self):
        missing = Path(self.temp.name) / "missing.csv"
        self.assertEqual(import_gateway_csv(missing, self.db), {"raw_imported": 0, "malformed": 0})
        self.assertEqual(gateway_metrics(self.db)["raw_events"], 0)

    def test_assistant_uses_mocked_provider_and_handles_provider_failure(self):
        class Models:
            def generate_content(self, **kwargs):
                return type("Response", (), {"text": "Mocked answer"})()
        class Client:
            models = Models()
        answer, provider = assistant_reply("Explain IDS", {}, api_key="test-key", client=Client())
        self.assertEqual((answer, provider), ("Mocked answer", "Gemini"))

        class BrokenModels:
            def generate_content(self, **kwargs):
                raise RuntimeError("provider unavailable")
        class BrokenClient:
            models = BrokenModels()
        answer, provider = assistant_reply("How do I connect a device?", {}, api_key="test-key", client=BrokenClient())
        self.assertIn("registered device(s)", answer)
        self.assertIn("fallback", provider)

    def test_gemini_status_is_safe_and_provider_errors_fall_back(self):
        status = gemini_config_status("dummy-secret-value")
        self.assertTrue(status["configured"])
        self.assertNotIn("dummy-secret-value", repr(status))
        self.assertEqual(status["model"], "gemini-3.8-flash")

        class ErrorModels:
            def __init__(self, message):
                self.message = message
            def generate_content(self, **kwargs):
                raise RuntimeError(self.message)
        for message, expected in (("401 invalid API key", "credentials or access"),
                                  ("429 quota exceeded", "quota"),
                                  ("connection refused", "network connection")):
            client = type("Client", (), {"models": ErrorModels(message)})()
            with self.subTest(category=expected):
                answer, provider = assistant_reply("How do I connect a device?", {},
                                                   api_key="dummy-secret-value", client=client)
                self.assertIn("registered device(s)", answer)
                self.assertIn(expected, provider)
                self.assertNotIn("dummy-secret-value", provider)

    def test_missing_gemini_key_is_reported_without_revealing_values(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            status = gemini_config_status()
            result = test_gemini_connection()
        self.assertFalse(status["configured"])
        self.assertIsNone(status["source"])
        self.assertEqual(result["status"], "Not configured")

    def test_gemini_connectivity_probe_sends_one_minimal_request(self):
        class Models:
            def __init__(self):
                self.calls = []
            def generate_content(self, **kwargs):
                self.calls.append(kwargs)
                return type("Response", (), {"text": "OK"})()
        class Client:
            def __init__(self):
                self.models = Models()
        client = Client()
        result = test_gemini_connection(api_key="dummy-secret", model="test-model", client=client)
        self.assertEqual(result["status"], "Connected")
        self.assertEqual(client.models.calls, [{"model": "test-model", "contents": "Reply with exactly: OK"}])
        self.assertNotIn("dummy-secret", repr(result))

    def test_gemini_connectivity_probe_classifies_model_and_timeout_errors(self):
        class StatusError(RuntimeError):
            def __init__(self, status_code):
                self.status_code = status_code
                super().__init__("provider rejected request")
        for error, category in ((RuntimeError("404 NOT_FOUND model"), "model is unavailable"),
                                (StatusError(400), "check key permissions"),
                                (TimeoutError("request timed out"), "request timed out")):
            client = type("Client", (), {"models": type("Models", (), {
                "generate_content": lambda self, **kwargs: (_ for _ in ()).throw(error)
            })()})()
            with self.subTest(category=category):
                result = test_gemini_connection(api_key="dummy-secret", client=client)
                self.assertEqual(result["status"], "Connection failed")
                self.assertIn(category, result["message"])
                self.assertNotIn("dummy-secret", repr(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
