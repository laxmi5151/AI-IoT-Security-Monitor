
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
import csv
from pathlib import Path
from collections import defaultdict, deque
import hmac
import os

# Track recent request times for each device
request_times = defaultdict(deque)

# Track whether each device is already in an alert state
device_in_alert = defaultdict(bool)

REQUEST_LIMIT = 10
TIME_WINDOW = 2
MAX_REQUEST_BYTES = 16 * 1024
GATEWAY_TOKEN = os.getenv("IOT_GATEWAY_TOKEN", "")
DEVICE_ID_MAX_LENGTH = 80

PROJECT_DIR = Path(__file__).resolve().parents[1]
EVENT_FILE = (
    PROJECT_DIR
    / "iot_simulator"
    / "data"
    / "processed"
    / "security_events.csv"
)
EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)

if not EVENT_FILE.exists():
    with EVENT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "timestamp",
            "device",
            "event",
            "requests_in_window"
        ])


class GatewayHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        token = GATEWAY_TOKEN
        if token:
            supplied = self.headers.get("Authorization", "")
            expected = "Bearer " + token
            if not hmac.compare_digest(supplied, expected):
                self.send_error(401, "Authentication required")
                return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(411, "Valid Content-Length required")
            return
        if content_length < 1 or content_length > MAX_REQUEST_BYTES:
            self.send_error(413, "Request body must be between 1 byte and 16 KB")
            return
        if "application/json" not in self.headers.get("Content-Type", "").lower():
            self.send_error(415, "Content-Type must be application/json")
            return
        data = self.rfile.read(content_length)

        try:
            device_data = json.loads(data.decode("utf-8"))
            if not isinstance(device_data, dict):
                raise ValueError("JSON body must be an object")
            device_name = device_data.get("device")
            if not isinstance(device_name, str) or not device_name.strip() or len(device_name) > DEVICE_ID_MAX_LENGTH:
                raise ValueError("device must be a non-empty string of at most 80 characters")
            for field in ("type", "value"):
                if field in device_data and not isinstance(device_data[field], (str, int, float, bool, type(None))):
                    raise ValueError(f"{field} must be a simple JSON value")
            device_name = "".join(char for char in device_name.strip() if char.isprintable())
            if not device_name:
                raise ValueError("device must contain printable characters")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400, "Invalid JSON")
            return
        except ValueError as error:
            self.send_error(400, str(error))
            return

        now = time.monotonic()
        times = request_times[device_name]
        times.append(now)

        # Keep only requests from the last TIME_WINDOW seconds
        while times and now - times[0] > TIME_WINDOW:
            times.popleft()

        request_count = len(times)

        print("\n--- IoT DATA RECEIVED ---")
        print("Device:", device_name)
        print("Telemetry payload omitted from logs")
        print("Requests in last 2 seconds:", request_count)

        if request_count >= REQUEST_LIMIT:
            if not device_in_alert[device_name]:
                print("WARNING: High request rate from", device_name)

                with EVENT_FILE.open(
                    "a", newline="", encoding="utf-8"
                ) as file:
                    writer = csv.writer(file)
                    writer.writerow([
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        device_name,
                        "High request rate",
                        request_count
                    ])

                device_in_alert[device_name] = True
            else:
                print("Alert already recorded for this ongoing burst")
        else:
            print("Request rate within demonstration limit")

            # Reset after the device's rolling request count falls
            # back to the permitted limit.
            device_in_alert[device_name] = False

        # The demo gateway records an alert at the normal threshold and sheds
        # extreme bursts so they cannot consume unlimited handler work.
        if request_count > REQUEST_LIMIT * 5:
            self.send_error(429, "Demo gateway rate limit exceeded")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Data received")


server = HTTPServer(("127.0.0.1", 5000), GatewayHandler)

print("IoT Gateway with request monitoring is running...")
print("Listening on http://127.0.0.1:5000")
if not GATEWAY_TOKEN:
    print("Local demo only: set IOT_GATEWAY_TOKEN before enabling any non-local receiver.")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\nGateway stopped.")
    server.server_close()
