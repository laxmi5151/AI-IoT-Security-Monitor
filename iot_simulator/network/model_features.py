
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[2]
FEATURE_FILE = PROJECT_DIR / "models" / "feature_columns.txt"


def convert_flows_for_model(flow_csv):
    """
    Prepare flow records for the CIC-IDS-2017 model.

    Only a CSV containing every named CIC-IDS model feature can be passed
    through. Compact IoT flow summaries do not contain enough evidence to
    reconstruct the missing training features, so they are rejected.
    """
    flow_csv = Path(flow_csv)

    if not flow_csv.exists():
        raise FileNotFoundError(
            f"Flow CSV not found: {flow_csv}"
        )

    from security_services import validate_model_frame

    flows = pd.read_csv(flow_csv, skipinitialspace=True)
    flows.columns = flows.columns.astype(str).str.strip()
    return validate_model_frame(flows)



if __name__ == "__main__":
    flow_file = (
        PROJECT_DIR
        / "iot_simulator"
        / "data"
        / "processed"
        / "iot_flow_features.csv"
    )

    # Step 1: Convert flow data into model-compatible columns
    converted = convert_flows_for_model(flow_file)

    print("Flow conversion completed.")
    print("Rows:", len(converted))
    print("Features:", len(converted.columns))
    print("\nFirst five rows:")
    print(converted.head().to_string(index=False))

    # Step 2: Load the trained AI model
    import joblib

    model_path = (
        PROJECT_DIR
        / "models"
        / "random_forest_ids.joblib"
    )

    model = joblib.load(model_path)

    # Step 3: Predict whether each flow is benign or an attack
    predictions = model.predict(converted)
    probabilities = model.predict_proba(converted)

    print("\n--- EXPERIMENTAL MODEL OUTPUT ---")
    print("Flows evaluated:", len(predictions))
    print("Predicted BENIGN:", int((predictions == 0).sum()))
    print("Predicted ATTACK:", int((predictions == 1).sum()))

    print("\nFirst five attack probabilities:")
    print(probabilities[:5, 1].round(3).tolist())

    # Step 4: Display a warning about prediction reliability
    print(
        "\nWARNING: These predictions are experimental only. "
        "Many features are missing or approximated, so the "
        "results are not reliable for real-world threat detection."
    )

