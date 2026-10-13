import requests
import time
import random
import os

SUSPICIOUS_MODE = os.getenv("SUSPICIOUS_MODE", "false").lower() == "true"

GATEWAY_URL = "http://127.0.0.1:5000"

print("📷 Camera-01 started")

if SUSPICIOUS_MODE:
    print("⚠️ SIMULATED SUSPICIOUS MODE: sending rapidly")
else:
    print("✅ NORMAL MODE: sending data every 5 seconds")

while True:
    camera_data = {
        "device": "Camera-01",
        "type": "smart_camera",
        "value": random.randint(1, 100)
    }

    try:
        response = requests.post(
            GATEWAY_URL,
            json=camera_data,
            timeout=3
        )
        print("Camera-01 → Gateway:", response.text)

    except requests.exceptions.RequestException:
        print("❌ Could not connect to Gateway")

    if SUSPICIOUS_MODE:
        time.sleep(0.2)
    else:
        time.sleep(5)
