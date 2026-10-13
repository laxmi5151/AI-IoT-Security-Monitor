# AI-IoT Security Monitor

A local-first Streamlit prototype for reviewing simulated IoT gateway events, registering devices, inspecting saved captures, and evaluating machine-learning experiments. It is a learning and investigation aid, not a production intrusion prevention system.

## Run on Windows

Open PowerShell in the project folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
streamlit run app.py
```

If the bundled environment is unavailable, create a Python 3.11 environment with `py -3.11 -m venv venv`, activate it, and install the listed requirements. Keep the original model and dataset files when upgrading dependencies.

## What the application does

- Stores device descriptions, incidents, analyst notes, status transitions, raw gateway rows, and model observations in SQLite.
- Imports `iot_simulator/data/processed/security_events.csv` incrementally. The legacy log currently contains 66,005 raw rows and 15,141 distinct timestamped detections. Those detections form 2 active gateway incidents under the configured five-minute grouping window. Repeated rows remain in raw evidence; they are not treated as proof of an attack.
- Interprets naive timestamps from the legacy gateway CSV as Asia/Kolkata local time, stores normalized UTC, and shows local timestamps in the interface.
- Supports incident status, severity, source, date, and text filters, pagination, audit history, and CSV/PDF exports.
- Keeps device registration separate from reachability and monitoring. No real device is shown online without a successful check.
- Provides a local read-only assistant fallback. Gemini is optional and requires a key configured through `.env` or a deployment secret store.
- Keeps the primary CIC-IDS Random Forest separate from the experimental IoT packet-window detector.

Incident grouping can be adjusted before app startup using `IOT_INCIDENT_DEDUPE_SECONDS` (1 to 86,400 seconds; default 300). This changes grouping for newly imported detections and does not erase existing incident evidence.

## Model inputs and evaluation

The primary saved model requires all 70 numeric features in exactly the schema listed in `models/feature_columns.txt`. Inference rejects missing, extra, nonnumeric, infinite, or empty input; no inference-time imputation or arbitrary field mapping is performed. The saved compact IoT flow file contains none of the exact required CIC-IDS field names and lacks reverse-flow counts, timing distributions, TCP flags, and related metadata. It cannot be converted reliably. The app explains this and provides separate experimental analysis for supported saved packet windows.

`train_model.py` now runs the reproducible grouped-capture experiment in `evaluate_grouped_model.py`. It writes candidate artifacts under `models/experiments/` and never replaces the existing primary model. The checked-in `evaluation_grouped_v1.json` records 55,000 sampled training rows, 10,000 validation rows from the Tuesday capture, and 9,745 test rows from the Friday DDoS capture. On the held-out Friday file, ATTACK precision was 0.9991, recall 0.6325, F1 0.7746, with false-positive rate 0.00065. On Tuesday validation, ATTACK recall was 0.0600 and F1 0.0889. These sampled results are dataset-specific evidence, not independent real-world or production effectiveness claims. The candidate is not selected by the app.

The separate packet-window model was trained from available normal and suspicious captures. Results on those same captures are demonstration results, not independent validation. Do not describe either model as confirmed detection or blocking.

## Assistant and secrets

The app works without Gemini credentials using deterministic local help responses. To enable Gemini, set `GEMINI_API_KEY` in the project-root `.env` file or configure it as a Streamlit secret. `GEMINI_MODEL` is optional and defaults to `gemini-3.8-flash`. The AI Security Assistant has a **Test Gemini connection** button that sends one minimal request with a 10-second timeout and no retries. It reports Not configured, Not tested, Connected, or Connection failed; key presence alone is never shown as a successful connection. Invalid credentials, unavailable models, quota limits, and network errors fall back to local help with a safe category message. The assistant sends a bounded context snapshot when the hosted provider is enabled; avoid including identifiers or data you do not want shared with that provider. Never paste keys into the dashboard, logs, source code, or Git. `.env` and Streamlit secrets are ignored by `.gitignore`.

For a local Windows setup, copy `.env.example` to `.env`, replace the empty `GEMINI_API_KEY=` value in `.env` with your own key, save, then stop and restart Streamlit. The example file intentionally contains no key. The project uses `python-dotenv` to load `.env` from the directory containing `security_services.py` (the project root), without overriding an already-set process environment variable.

`AI_IOT_DB_PATH` optionally selects a durable SQLite path. `IOT_GATEWAY_TOKEN` optionally protects the existing local demo receiver. Keep that receiver bound to localhost unless it is deployed behind authenticated HTTPS. There is no remote authenticated gateway ingestion service in this project.

## Tests and demo

```powershell
python -m unittest discover -s tests -v
python test_model.py
python test_iot_detector.py
python -m py_compile app.py security_services.py evaluate_grouped_model.py train_model.py scripts/demo_incident_workflow.py
python scripts/demo_incident_workflow.py
```

The deterministic workflow demo uses a temporary database, records one synthetic normal observation, imports a single request-rate fixture, reviews it, and generates CSV/PDF reports. It sends no packets and scans no device. The Streamlit UI can also be exercised with its AppTest framework when available in the installed Streamlit version.

Run a fresh grouped-capture experiment with:

```powershell
python evaluate_grouped_model.py
```

Use `--force` only when intentionally regenerating the versioned experiment outputs. This does not replace the app's primary model.

## Troubleshooting

- **Model won't load:** verify `models/random_forest_ids.joblib`, `models/feature_columns.txt`, and the Python environment. The joblib artifact must be treated as trusted project content.
- **CSV rejected:** provide the exact 70 saved feature names with numeric finite values. Compact IoT summaries are not equivalent CIC-IDS input.
- **Gateway history unavailable:** verify the CSV header is `timestamp,device,event,requests_in_window`; malformed rows are counted and retained in the source file for correction.
- **Gemini does not respond:** local fallback is expected without a key, optional package, network, quota, or provider availability.
- **Database missing after redeployment:** configure persistent storage for the SQLite file; ephemeral hosting storage is not durable.
- **Real traffic not shown:** registration is descriptive. Live capture, network discovery, remote ingestion, and automatic blocking are not implemented.

## Verified limitations

The dashboard's saved-history counts are not live network telemetry. This prototype does not discover devices, monitor continuous traffic, test real reachability, automatically block activity, or provide a secured cloud receiver. The local demo gateway is not suitable as an unauthenticated public endpoint. Real deployment requires an authorized sensor/gateway, authentication, HTTPS, durable database storage, and separate evaluation on representative independent captures.

## Dependencies

Runtime dependencies are listed in `requirements.txt`: Streamlit, pandas, NumPy, scikit-learn, joblib, Plotly, Scapy, python-dotenv, and the Google GenAI Python SDK (`google-genai`). The assistant remains in local-help mode if the SDK is missing. Pytest is listed for development; the included service suite also runs with Python's standard `unittest` runner.

## Project layout and submission notes

- `app.py` contains the Streamlit dashboard and page routing.
- `security_services.py` contains database, device, incident, assistant, and Gemini configuration services.
- `models/` contains the existing primary CIC-IDS model, feature schema, and experimental model artifacts. The primary Random Forest artifact is about 5.1 MB, below GitHub's 100 MiB per-file limit.
- `iot_simulator/` contains the recorded gateway event history used for the demonstration. These are saved records, not a live network feed.
- `iot_simulator/data/processed/` contains the small derived packet/flow feature files needed by the experimental IoT detector. Raw packet capture files under `captures/` and `iot_simulator/data/training/` remain local and are excluded from Git.
- `dataset/` and `MachineLearningCVE/` are local working locations for the CIC-IDS CSV captures. The raw capture CSVs are excluded from Git because several exceed 100 MiB and the directories contain duplicate copies. Keep your local copies; obtain the CIC-IDS dataset from its official distribution if you need to reproduce training/evaluation. The app's saved models do not require committing these raw archives.
- `tests/` contains automated service and security tests.

The `.gitignore` excludes API secrets, local databases, virtual environments, caches, temporary/back-up files, raw packet captures, bundled Wireshark binaries, and raw CIC-IDS CSVs. `.env.example` is a template with an empty API-key value. Before publishing, inspect `git status --short`, `git diff --cached --name-only`, and staged file sizes; never stage `.env`, `.streamlit/secrets.toml`, a virtual environment, or raw dataset archives. If a real key was ever committed, rotate it with Google; deleting it from the latest revision does not remove it from Git history.

## Validation recorded for this submission

The available automated checks completed in the project environment:

- `python -m unittest discover -s tests -v`: 18 tests passed.
- `python test_model.py`: model loaded with the 70-feature schema and returned a synthetic smoke-test prediction. This checks the pipeline, not detection quality.
- `python test_iot_detector.py`: completed on the saved normal/suspicious captures; these are demonstration results on captures used during development.
- `python -m py_compile app.py security_services.py tests\test_security_services.py`: passed.
- `python -m pip check`: reported no broken installed dependency requirements. The existing local environment has pandas 3 and Plotly 7, while `requirements.txt` intentionally constrains pandas below 3 and Plotly below 7. The tests passed in the existing environment, but a fresh environment using the declared major-version bounds was not separately tested here.
- The tests use the standard-library `unittest` runner. Pytest is listed for development but was not installed in this environment.

A Streamlit `AppTest` run did not complete within the available timeout, and the environment blocked a localhost HTTP health check. Therefore interactive navigation through every page and a browser-level launch are not claimed as verified here. The primary model rejects the compact saved flow CSV because it lacks the required CIC-IDS features; the UI reports this limitation instead of fabricating a prediction.

Gemini was not successfully connected during this validation. The configured model is `gemini-3.8-flash`; a single minimal request failed with a provider/service-unavailable category. No successful response was received, so the UI must remain `Connection failed`; deterministic local help remains available. The model identifier is listed in Google's current model documentation, but a listed model and configured key do not prove that a particular account can use it.

