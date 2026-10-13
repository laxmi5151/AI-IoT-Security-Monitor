import requests
import time
import random


GATEWAY_URL = "http://127.0.0.1:5000"


print("💡 Smart-Light-01 started")
print("Sending light status to the IoT Gateway...")


while True:

    brightness = random.randint(0, 100)

    light_data = {
        "device": "Smart-Light-01",
        "type": "smart_light",
        "value": brightness
    }

    try:

        response = requests.post(
            GATEWAY_URL,
            json=light_data
        )

        print(
            "Smart-Light-01 → Gateway:",
            brightness,
            "% brightness |",
            response.text
        )

    except requests.exceptions.RequestException:

        print("❌ Could not connect to Gateway")

    time.sleep(7)