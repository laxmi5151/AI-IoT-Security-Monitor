
from pathlib import Path
import joblib
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent
MODEL_PATH = PROJECT_DIR / "models" / "random_forest_ids.joblib"
FEATURE_PATH = PROJECT_DIR / "models" / "feature_columns.txt"

print("Loading trained AI model...")

model = joblib.load(MODEL_PATH)
feature_columns = FEATURE_PATH.read_text(
    encoding="utf-8"
).splitlines()

print("Model loaded successfully!")
print("Number of expected features:", len(feature_columns))

# Temporary test input: zeros for every feature.
# This checks that the model can make a prediction;
# it does NOT represent real network traffic.
test_data = pd.DataFrame(
    [[0] * len(feature_columns)],
    columns=feature_columns
)

prediction = model.predict(test_data)[0]
probabilities = model.predict_proba(test_data)[0]

print("\n--- TEST PREDICTION ---")
print("Prediction:", "ATTACK" if prediction == 1 else "BENIGN")
print("BENIGN probability:", round(probabilities[0] * 100, 2), "%")
print("ATTACK probability:", round(probabilities[1] * 100, 2), "%")

print("\nModel test completed.")


print("\n--- MODEL FEATURE NAMES ---")
print(feature_columns)
