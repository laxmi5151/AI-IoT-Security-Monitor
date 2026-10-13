import requests
import time
import random


GATEWAY_URL = "http://127.0.0.1:5000"


print("🌡️ Temperature-01 started")
print("Sending temperature readings to the IoT Gateway...")


while True:

    temperature = round(
        random.uniform(22.0, 30.0),
        2
    )

    sensor_data = {
        "device": "Temperature-01",
        "type": "temperature_sensor",
        "value": temperature
    }

    try:

        response = requests.post(
            GATEWAY_URL,
            json=sensor_data
        )

        print(
            "Temperature-01 → Gateway:",
            temperature,
            "°C |",
            response.text
        )

    except requests.exceptions.RequestException:

        print("❌ Could not connect to Gateway")

    time.sleep(10)