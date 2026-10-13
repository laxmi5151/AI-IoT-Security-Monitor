
from pathlib import Path
import glob
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)

PROJECT_DIR = Path(__file__).resolve().parent
DATASET_DIR = PROJECT_DIR / "dataset"
MODEL_DIR = PROJECT_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

SAMPLES_PER_FILE = 10000
RANDOM_STATE = 42



def load_dataset():
    files = sorted(DATASET_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {DATASET_DIR}"
        )

    sampled_data = []

    for file in files:
        print(f"\nReading: {file.name}")
        file_samples = []
        rows_selected = 0

        try:
            for chunk in pd.read_csv(
                file,
                chunksize=25000,
                low_memory=False,
                skipinitialspace=True
            ):
                chunk.columns = chunk.columns.str.strip()

                if "Label" not in chunk.columns:
                    continue

                chunk["Label"] = (
                    chunk["Label"].astype(str).str.strip()
                )

                chunk["target"] = (
                    chunk["Label"].str.upper() != "BENIGN"
                ).astype(int)

                remaining = SAMPLES_PER_FILE - rows_selected

                if remaining <= 0:
                    break

                take = min(1000, remaining, len(chunk))

                if take > 0:
                    selected = chunk.sample(
                        n=take,
                        random_state=RANDOM_STATE
                    )
                    file_samples.append(selected)
                    rows_selected += len(selected)

        except Exception as error:
            print(f"Could not read {file.name}: {error}")
            raise

        if file_samples:
            sampled_data.extend(file_samples)
            print(f"Rows selected: {rows_selected}")
        else:
            print("No usable rows found in this file.")

    if not sampled_data:
        raise ValueError("No usable CSV data was found.")

    data = pd.concat(sampled_data, ignore_index=True)
    del sampled_data

    print("\nCombined sampled rows:", len(data))
    print("\nClass distribution:")
    print(
        data["target"]
        .map({0: "BENIGN", 1: "ATTACK"})
        .value_counts()
    )

    return data



def prepare_features(data):
    # Remove labels and any identifying text columns
    drop_columns = ["Label", "target", "Flow ID", "Source IP", "Destination IP", "Timestamp"]
    X = data.drop(
        columns=[col for col in drop_columns if col in data.columns],
        errors="ignore"
    ).copy()

    y = data["target"].copy()

    # Remove duplicate feature columns
    X = X.loc[:, ~X.columns.duplicated()]

    # Convert features to numeric; invalid values become missing
    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    # Replace infinite values and fill missing values
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Remove features that contain no variation
    X = X.loc[:, X.nunique(dropna=False) > 1]

    return X, y


def main():
    """Use the versioned grouped-capture experiment; never replace the primary model."""
    import argparse
    from evaluate_grouped_model import run

    parser = argparse.ArgumentParser(description="Train/evaluate a versioned grouped-file candidate model.")
    parser.add_argument("--force", action="store_true", help="replace only the existing grouped experiment artifacts")
    run(parser.parse_args().force)


if __name__ == "__main__":
    main()
