"""Train and evaluate an isolated CIC-IDS experiment with whole-file holdouts.

This never replaces the deployed random_forest_ids.joblib. It writes a
versioned candidate and a metrics report under models/experiments/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "dataset"
OUTPUT_DIR = ROOT / "models" / "experiments"
VALIDATION_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
RANDOM_STATE = 42
SAMPLES_PER_FILE = 10000
CHUNK_ROWS = 25000


def sample_capture(path: Path, limit: int = SAMPLES_PER_FILE) -> pd.DataFrame:
    samples, selected, chunk_index = [], 0, 0
    for chunk in pd.read_csv(path, chunksize=CHUNK_ROWS, low_memory=False,
                             skipinitialspace=True, encoding="utf-8",
                             encoding_errors="replace"):
        chunk.columns = chunk.columns.astype(str).str.strip()
        if "Label" not in chunk:
            raise ValueError(f"{path.name} has no Label column")
        remaining = limit - selected
        if remaining <= 0:
            break
        take = min(1000, remaining, len(chunk))
        if take:
            samples.append(chunk.sample(n=take, random_state=RANDOM_STATE + chunk_index))
            selected += take
        chunk_index += 1
    if not samples:
        raise ValueError(f"No records sampled from {path.name}")
    data = pd.concat(samples, ignore_index=True)
    data["Label"] = data["Label"].astype(str).str.strip()
    data["target"] = (data["Label"].str.upper() != "BENIGN").astype("int8")
    data["_capture_file"] = path.name
    return data


def prepare_features(frame: pd.DataFrame, feature_names: list[str] | None = None):
    drop = ["Label", "target", "Flow ID", "Source IP", "Destination IP", "Timestamp", "_capture_file"]
    features = frame.drop(columns=[c for c in drop if c in frame], errors="ignore").copy()
    features = features.loc[:, ~features.columns.duplicated()]
    for name in features:
        features[name] = pd.to_numeric(features[name], errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
    if feature_names is None:
        features = features.loc[:, features.nunique(dropna=False) > 1]
        feature_names = list(features.columns)
    else:
        absent = [name for name in feature_names if name not in features]
        if absent:
            raise ValueError(f"Evaluation data is missing trained features: {absent[:8]}")
        features = features.loc[:, feature_names]
    return features, frame["target"].astype(int), feature_names


def evaluate(model, frame: pd.DataFrame, feature_names: list[str], name: str) -> dict:
    features, actual, _ = prepare_features(frame, feature_names)
    predicted = model.predict(features)
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in matrix.ravel())
    precision, recall, f1, supports = precision_recall_fscore_support(
        actual, predicted, labels=[0, 1], zero_division=0)
    result = {
        "dataset": name,
        "files": sorted(frame["_capture_file"].unique().tolist()),
        "sample_count": len(frame),
        "class_counts": {"BENIGN": int((actual == 0).sum()), "ATTACK": int((actual == 1).sum())},
        "confusion_matrix_actual_rows_predicted_columns": matrix.tolist(),
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "per_class": {label: {"precision": float(precision[i]), "recall": float(recall[i]),
                               "f1": float(f1[i]), "support": int(supports[i])}
                       for i, label in enumerate(("BENIGN", "ATTACK"))},
        "classification_report": classification_report(actual, predicted, labels=[0, 1],
                                                        target_names=["BENIGN", "ATTACK"],
                                                        output_dict=True, zero_division=0),
    }
    if hasattr(model, "predict_proba") and len(set(actual)) == 2:
        result["roc_auc"] = float(roc_auc_score(actual, model.predict_proba(features)[:, list(model.classes_).index(1)]))
    else:
        result["roc_auc"] = None
    return result


def run(force: bool = False) -> dict:
    files = sorted(DATA_DIR.glob("*.csv"))
    by_name = {file.name: file for file in files}
    if VALIDATION_FILE not in by_name or TEST_FILE not in by_name:
        raise FileNotFoundError(f"Expected holdout files: {VALIDATION_FILE} and {TEST_FILE}")
    test_file, validation_file = by_name[TEST_FILE], by_name[VALIDATION_FILE]
    training_files = [file for file in files if file not in {test_file, validation_file}]
    if not training_files:
        raise ValueError("No training captures remain after selecting whole-file holdouts.")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = OUTPUT_DIR / "random_forest_ids_grouped_v1.joblib"
    features_path = OUTPUT_DIR / "feature_columns_grouped_v1.txt"
    report_path = OUTPUT_DIR / "evaluation_grouped_v1.json"
    if not force and any(p.exists() for p in (model_path, features_path, report_path)):
        raise FileExistsError("Versioned experiment outputs already exist. Review them or rerun with --force to replace this experiment.")

    train_parts = [sample_capture(file) for file in training_files]
    validation = sample_capture(validation_file)
    test = sample_capture(test_file)
    train = pd.concat(train_parts, ignore_index=True)
    x_train, y_train, feature_names = prepare_features(train)
    if y_train.nunique() != 2:
        raise ValueError("Training captures did not produce both BENIGN and ATTACK classes.")
    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE,
                                   n_jobs=-1, class_weight="balanced")
    model.fit(x_train, y_train)
    metrics = {
        "experiment": "grouped-capture file holdout v1; candidate only, not selected by the app",
        "random_state": RANDOM_STATE,
        "sampling": {"per_file_maximum": SAMPLES_PER_FILE, "chunk_rows": CHUNK_ROWS,
                     "method": "deterministic sample of up to 1000 records per CSV chunk"},
        "preprocessing": {"drop": ["Label", "target", "Flow ID", "Source IP", "Destination IP", "Timestamp"],
                          "numeric_conversion": "errors to NaN", "missing_and_infinite": "replace/fill with zero",
                          "constant_features_removed_using_training_data_only": True,
                          "scaler": None},
        "training_files": [file.name for file in training_files],
        "training_samples": len(train),
        "training_class_counts": {"BENIGN": int((y_train == 0).sum()), "ATTACK": int((y_train == 1).sum())},
        "feature_count": len(feature_names),
        "validation": evaluate(model, validation, feature_names, "validation"),
        "test": evaluate(model, test, feature_names, "held-out capture file"),
        "limitations": "Metrics apply only to deterministic sampled rows from the named held-out capture files; they are not production or real-network effectiveness claims.",
    }
    model_tmp = model_path.with_name(model_path.name + ".tmp")
    features_tmp = features_path.with_name(features_path.name + ".tmp")
    report_tmp = report_path.with_name(report_path.name + ".tmp")
    try:
        joblib.dump(model, model_tmp)
        features_tmp.write_text("\n".join(feature_names), encoding="utf-8")
        metrics["artifact_sha256"] = hashlib.sha256(model_tmp.read_bytes()).hexdigest()
        report_tmp.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(model_tmp, model_path)
        os.replace(features_tmp, features_path)
        os.replace(report_tmp, report_path)
    except Exception:
        model_tmp.unlink(missing_ok=True)
        features_tmp.unlink(missing_ok=True)
        report_tmp.unlink(missing_ok=True)
        raise
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="overwrite only this versioned experiment's outputs")
    run(parser.parse_args().force)
