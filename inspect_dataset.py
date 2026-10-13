
from pathlib import Path
import pandas as pd

# Find the dataset folder in the project
PROJECT_DIR = Path(__file__).resolve().parent
DATASET_DIR = PROJECT_DIR / "dataset"

csv_files = sorted(DATASET_DIR.glob("*.csv"))

print("CIC-IDS-2017 Dataset Inspection")
print("=" * 40)
print("Dataset folder:", DATASET_DIR)
print("CSV files found:", len(csv_files))

for file in csv_files:
    print("\nFile:", file.name)
    print("Size (MB):", round(file.stat().st_size / (1024 * 1024), 2))

    try:
        # Read only the first 5 rows for a quick inspection
        df = pd.read_csv(file, nrows=5, low_memory=False)
        df.columns = df.columns.str.strip()

        print("Columns:", len(df.columns))
        print("First 10 column names:")
        print(df.columns[:10].tolist())

        label_columns = [
            col for col in df.columns
            if "label" in col.lower()
        ]
        print("Possible label columns:", label_columns)

    except Exception as error:
        print("Could not inspect this file:", error)

print("\nInspection complete.")
