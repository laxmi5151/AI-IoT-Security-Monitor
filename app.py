
import streamlit as st
import pandas as pd
import joblib
from pathlib import Path
import time
from security_services import (
    DEVICE_CATEGORIES, add_observation, assistant_reply, app_context, count_incidents,
    create_alert, device_status_counts, export_incidents_csv,
    export_incidents_pdf, flow_compatibility_report, format_local_timestamp,
    gemini_config_status, gateway_metrics, import_gateway_csv, incident_audit, incident_metrics,
    init_db, list_devices, list_incident_events, list_incident_sources,
    list_incidents, remove_device, safe_predict_flows, save_device,
    model_diagnostics, test_gemini_connection, update_incident,
)
# -------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------
st.set_page_config(
    page_title="AI-IoT Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------------------------------------
# FRIENDLY MODERN UI STYLES
# -------------------------------------------------
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2.5rem; max-width: 1400px;}
    [data-testid="stMetric"] {background: rgba(128,128,128,0.08); border: 1px solid rgba(128,128,128,0.18); padding: 14px 16px; border-radius: 14px;}
    div.stButton > button {border-radius: 10px; min-height: 2.7rem; font-weight: 600;}
    div[data-testid="stExpander"] {border-radius: 12px; border: 1px solid rgba(128,128,128,0.22);}
    .friendly-note {padding: 14px 16px; border-radius: 12px; background: rgba(100,120,160,0.10); border: 1px solid rgba(100,120,160,0.22);}
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------------------------------
# LOAD TRAINED AI MODEL
# -------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent
init_db()
MODEL_PATH = PROJECT_DIR / "models" / "random_forest_ids.joblib"
FEATURE_PATH = PROJECT_DIR / "models" / "feature_columns.txt"
IOT_MODEL_PATH = PROJECT_DIR / "models" / "iot_traffic_detector.joblib"
@st.cache_resource
def load_ai_model():
    model = joblib.load(MODEL_PATH)
    feature_columns = FEATURE_PATH.read_text(
        encoding="utf-8"
    ).splitlines()
    return model, feature_columns
try:
    ai_model, feature_columns = load_ai_model()
    model_loaded = True
except Exception as error:
    ai_model = None
    feature_columns = []
    model_loaded = False
    st.sidebar.error(f"AI model could not load: {error}")
# -------------------------------------------------
# LOAD EXPERIMENTAL IOT TRAFFIC DETECTOR
# -------------------------------------------------
@st.cache_resource
def load_iot_detector():
    return joblib.load(IOT_MODEL_PATH)
try:
    iot_detector_data = load_iot_detector()
    iot_detector = iot_detector_data["model"]
    iot_detector_features = iot_detector_data["features"]
    iot_window_seconds = iot_detector_data["window_seconds"]
    iot_detector_loaded = True
except Exception as error:
    iot_detector = None
    iot_detector_features = []
    iot_window_seconds = 2
    iot_detector_loaded = False
    st.sidebar.warning(f"IoT detector unavailable: {error}")
# -------------------------------------------------
# LOAD PROCESSED IOT FLOW DATA
# -------------------------------------------------
FLOW_FILE = (
    PROJECT_DIR
    / "iot_simulator"
    / "data"
    / "processed"
    / "iot_flow_features.csv"
)
@st.cache_data
def load_flow_data():
    if FLOW_FILE.exists():
        return pd.read_csv(FLOW_FILE)
    return pd.DataFrame()
try:
    flow_data = load_flow_data()
except Exception as error:
    flow_data = pd.DataFrame()
    st.sidebar.warning(f"Could not load flow data: {error}")
EVENT_FILE = (
    PROJECT_DIR
    / "iot_simulator"
    / "data"
    / "processed"
    / "security_events.csv"
)
@st.cache_data(show_spinner="Importing saved gateway history on first run...")
def sync_gateway_history(file_path: str, modified_ns: int, file_size: int):
    return import_gateway_csv(file_path)

try:
    if EVENT_FILE.exists():
        file_stat = EVENT_FILE.stat()
        gateway_import_result = sync_gateway_history(str(EVENT_FILE), file_stat.st_mtime_ns, file_stat.st_size)
    else:
        gateway_import_result = {"raw_imported": 0, "malformed": 0}
    gateway_state = gateway_metrics()
except Exception as error:
    gateway_import_result = {"raw_imported": 0, "malformed": 0}
    gateway_state = {"raw_events": 0, "unique_detections": 0, "incidents": 0,
                     "unresolved_incidents": 0, "last_received_utc": None,
                     "unresolved_by_severity": {}, "malformed_rows": 0}
    st.sidebar.warning(f"Gateway history is unavailable: {error}")
# -------------------------------------------------
# SESSION STATE
# -------------------------------------------------
if "threat_detected" not in st.session_state:
    st.session_state.threat_detected = False
if "custom_iot_devices" not in st.session_state:
    st.session_state.custom_iot_devices = []


def render_incident_browser(prefix: str, *, downloads: bool = False):
    st.caption("Gateway rule events are anomalies for review, not confirmed attacks. Every raw log line is retained in SQLite.")
    sources = ["All", *list_incident_sources()]
    f1, f2, f3 = st.columns(3)
    with f1:
        selected_status = st.selectbox("Incident status", ["All", "Open", "Acknowledged", "Investigating", "Resolved"], key=f"{prefix}_status")
    with f2:
        selected_severity = st.selectbox("Severity", ["All", "Informational", "Low", "Medium", "High", "Critical"], key=f"{prefix}_severity")
    with f3:
        selected_source = st.selectbox("Source", sources, key=f"{prefix}_source")
    d1, d2, d3 = st.columns([1, 1, 2])
    with d1:
        start_date = st.date_input("From date", value=None, key=f"{prefix}_start_date")
    with d2:
        end_date = st.date_input("To date", value=None, key=f"{prefix}_end_date")
    with d3:
        search = st.text_input("Search device, rule, evidence, or source", max_chars=100, key=f"{prefix}_search")
    start_iso = start_date.isoformat() if start_date else None
    end_iso = end_date.isoformat() if end_date else None
    filters = {"status": selected_status, "severity": selected_severity, "source": selected_source,
               "start_utc": start_iso, "end_utc": end_iso, "search": search}
    filter_signature = tuple(filters.values())
    sig_key, page_key = f"{prefix}_filter_signature", f"{prefix}_page_number"
    if st.session_state.get(sig_key) != filter_signature:
        st.session_state[sig_key] = filter_signature
        st.session_state[page_key] = 0
    page_number = int(st.session_state.get(page_key, 0))
    page_size = st.selectbox("Incidents per page", [10, 25, 50], index=1, key=f"{prefix}_page_size")
    total = count_incidents(**filters)
    incidents = list_incidents(limit=page_size, offset=page_number * page_size, **filters)
    st.caption(f"Showing {len(incidents)} of {total:,} matching incidents · Page {page_number + 1} · Timestamps shown in local time (Asia/Kolkata).")
    if not incidents:
        st.info("No incidents match these filters. The historical gateway source currently contains only request-rate rule events.")
    for incident in incidents:
        title = f"{incident['severity']} · {incident['status']} · {incident['device_name'] or 'Unassociated'} · {format_local_timestamp(incident['last_seen'])}"
        with st.expander(title):
            st.write(f"**Incident ID:** `{incident['incident_id']}`")
            st.write(f"**Detection:** {incident['method']} · **Source:** {incident['source']}")
            st.write(f"**First seen:** {format_local_timestamp(incident['first_seen'])} · **Last seen:** {format_local_timestamp(incident['last_seen'])}")
            st.write(f"**Occurrences:** {incident['occurrence_count']:,} distinct detections from **{incident['raw_occurrence_count']:,} raw log rows**")
            st.write("**Evidence:** " + incident["evidence"])
            st.info("**Recommendation:** " + incident["recommendation"])
            if incident["model_version"]:
                st.caption(f"Model version: {incident['model_version']}")
            note = st.text_area("Analyst notes", value=incident["analyst_notes"], max_chars=1000,
                                key=f"{prefix}_note_{incident['incident_id']}", height=70)
            actions = st.columns(5)
            if incident["status"] == "Open" and actions[0].button("Acknowledge", key=f"{prefix}_ack_{incident['incident_id']}"):
                update_incident(incident["incident_id"], "acknowledge", note=note)
                st.rerun()
            if incident["status"] != "Resolved" and actions[1].button("Investigate", key=f"{prefix}_investigate_{incident['incident_id']}"):
                update_incident(incident["incident_id"], "investigate", note=note)
                st.rerun()
            if incident["status"] != "Resolved" and actions[2].button("Resolve", key=f"{prefix}_resolve_{incident['incident_id']}"):
                update_incident(incident["incident_id"], "resolve", note=note)
                st.rerun()
            if incident["status"] == "Resolved" and actions[3].button("Reopen", key=f"{prefix}_reopen_{incident['incident_id']}"):
                update_incident(incident["incident_id"], "reopen", note=note)
                st.rerun()
            if actions[4].button("Save note", key=f"{prefix}_save_note_{incident['incident_id']}"):
                update_incident(incident["incident_id"], "note", note=note)
                st.success("Note saved to the incident audit trail.")
            history = incident_audit(incident["incident_id"])
            if history:
                with st.expander("Analyst action history"):
                    st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
            raw_evidence = list_incident_events(incident["incident_id"], limit=25)
            if raw_evidence:
                with st.expander("Recent raw gateway rows (up to 25)"):
                    raw_frame = pd.DataFrame(raw_evidence)
                    raw_frame["event_time_utc"] = raw_frame["event_time_utc"].map(format_local_timestamp)
                    st.dataframe(raw_frame, use_container_width=True, hide_index=True)
    pg1, pg2, _ = st.columns([1, 1, 4])
    pg1.button("← Previous", key=f"{prefix}_previous", disabled=page_number == 0,
               on_click=lambda k=page_key: st.session_state.__setitem__(k, max(0, st.session_state.get(k, 0) - 1)))
    pg2.button("Next →", key=f"{prefix}_next", disabled=(page_number + 1) * page_size >= total,
               on_click=lambda k=page_key: st.session_state.__setitem__(k, st.session_state.get(k, 0) + 1))
    if downloads:
        export_args = dict(filters)
        st.download_button("Download filtered CSV", export_incidents_csv(**export_args),
                           file_name="ai_iot_incidents.csv", mime="text/csv", key=f"{prefix}_csv")
        st.download_button("Download filtered PDF", export_incidents_pdf(**export_args),
                           file_name="ai_iot_incidents.pdf", mime="application/pdf", key=f"{prefix}_pdf")

# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------
st.sidebar.title("🛡️ IoT Security")
st.sidebar.caption("A guided network-security demo")
st.sidebar.info("Start at **Overview**, then use the pages in order. This prototype analyzes recorded traffic and simulated events.")
if model_loaded:
    st.sidebar.success("AI Model: Loaded")
else:
    st.sidebar.error("AI Model: Unavailable")

def navigate_to(destination):
    st.session_state.active_page = destination

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "🔌 Connect Device",
        "🧠 AI Security Assistant",
        "📡 IoT Devices",
        "🔍 Live Monitoring",
        "🚨 Threats",
        "📜 Event History",
        "📘 User Guide",
        "📄 Reports",
        "⚙️ Settings & Health",
    ],
    key="active_page",
)
st.sidebar.divider()
st.sidebar.caption("AI-Based IoT Network Intrusion Detection System")
st.sidebar.caption("College prototype · Demo mode")
# -------------------------------------------------
# OVERVIEW
# -------------------------------------------------
if page == "📊 Overview":
    st.title("🛡️ AI-IoT Security Monitor")
    st.markdown("""<div class="friendly-note"><b>Welcome!</b> This app demonstrates how unusual activity in simulated IoT network traffic can be reviewed using machine-learning experiments and gateway rules. Choose a page from the sidebar to get started.</div>""", unsafe_allow_html=True)
    action_connect, action_assistant = st.columns(2, gap="large")
    with action_connect:
        with st.container(border=True):
            st.subheader("🔌 Connect a device")
            st.write("Register and manage your IoT device details.")
            st.caption("Registration is local; it does not connect to the physical device.")
            st.button("＋ Add or manage devices", type="primary", use_container_width=True,
                      on_click=navigate_to, args=("🔌 Connect Device",), key="overview_connect_cta")
    with action_assistant:
        with st.container(border=True):
            st.subheader("🧠 AI Security Assistant")
            st.write("Ask about alerts, devices, model results, and monitoring limits.")
            st.caption("Uses local help by default; Gemini is optional.")
            st.button("Ask the security assistant", type="primary", use_container_width=True,
                      on_click=navigate_to, args=("🧠 AI Security Assistant",), key="overview_assistant_cta")
    st.write("")
    st.divider()
    device_counts = device_status_counts()
    incident_counts = incident_metrics()
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Registered", sum(device_counts.values()))
    col2.metric("Reachable", device_counts["Reachable"])
    col3.metric("Monitored", device_counts["Monitored"], help="Only devices with a verified traffic source count as monitored.")
    col4.metric("Unresolved incidents", incident_counts["unresolved"])
    col5.metric("Last gateway data", format_local_timestamp(gateway_state.get("last_received_utc")))
    st.caption(f"Mode: historical/simulation only · Live monitoring: inactive · Model: {'loaded' if model_loaded else 'unavailable'} · Database: available. Last data time refers to the newest event in the saved gateway log.")
    st.subheader("Gateway log and incident totals")
    g1, g2, g3, g4 = st.columns(4)
    g1.metric("Raw gateway rows", f"{gateway_state['raw_events']:,}")
    g2.metric("Unique detections", f"{gateway_state['unique_detections']:,}")
    g3.metric("Grouped incidents", f"{gateway_state['incidents']:,}")
    g4.metric("Unresolved", f"{gateway_state['unresolved_incidents']:,}")
    st.caption("Historical data imported from the local gateway CSV. Duplicate rows remain available as evidence; event timestamps are interpreted as Asia/Kolkata local time and stored in UTC.")
    if gateway_state["unresolved_by_severity"]:
        st.write("Unresolved by severity: " + " · ".join(f"{name}: {count}" for name, count in gateway_state["unresolved_by_severity"].items()))
    st.divider()
    st.subheader("📡 Demonstration device profiles")
    st.caption("Examples only — no reachability check has been run.")
    devices = {
        "📷 Camera-01": "Demo profile",
        "🌡️ Temperature-01": "Demo profile",
        "💡 Smart-Light-01": "Demo profile",
        "🏠 Gateway-01": "Demo profile"
    }
    for device, status in devices.items():
        st.write(f"**{device}** — {status}")
    latest_incidents = list_incidents(limit=5)
    if latest_incidents:
        st.subheader("Recent incident timeline")
        st.dataframe(pd.DataFrame([{"Last seen": format_local_timestamp(item["last_seen"]),
                                   "Severity": item["severity"], "Status": item["status"],
                                   "Source": item["source"], "Device": item["device_name"],
                                   "Occurrences": item["occurrence_count"],
                                   "Latest evidence": item["evidence"]} for item in latest_incidents]),
                     use_container_width=True, hide_index=True)
        st.button("Investigate incidents", on_click=navigate_to, args=("📜 Event History",), key="overview_incidents_cta")
    st.divider()
    # Guided, explicitly simulated demo action
    st.subheader("🧪 Try a demo alert")
    st.write("This button creates an example alert inside the app. It does not send traffic or scan a real device.")
    col_a, col_b = st.columns([1, 3])
    with col_a:
        if st.button("Create example alert", type="primary", use_container_width=True):
            st.session_state.threat_detected = True
            st.session_state.demo_alert_created = True
            create_alert(
                "Camera-01", "simulated dashboard scenario", "demonstration rule",
                "A controlled example alert was requested by the operator.", "Medium",
                "This is a synthetic example; no packet or device observation was made.",
                "The button created a demonstration record only; it is not evidence of malicious activity.",
                "Review the example, then verify any real concern using an authorized traffic source.",
            )
            st.success("Example alert created. Open **Threats** to read the explanation and recommended checks.")
    with col_b:
        if st.button("Reset example alert", use_container_width=True):
            st.session_state.threat_detected = False
            st.session_state.demo_alert_created = False
            st.info("Example alert cleared from this session.")
# -------------------------------------------------
# IOT DEVICES
# -------------------------------------------------
elif page == "📡 IoT Devices":
    st.title("📡 IoT Devices")
    st.write("Registered descriptions and illustrative built-in devices.")
    st.caption("Registration is stored locally. It does not establish a real device connection or prove traffic monitoring.")
    registered_devices = list_devices()
    if registered_devices:
        for device in registered_devices:
            c1, c2, c3, c4 = st.columns([3, 2, 1, 1])
            c1.write(f"**{device['name']}** — {device['category']}")
            c2.write(device['room'] or device['address'] or "No room/address supplied")
            c3.write(device["monitoring_status"])
            if c4.button("Remove", key=f"remove_persisted_{device['id']}"):
                remove_device(device['id'])
                st.rerun()
            with st.expander(f"Edit {device['name']}"):
                with st.form(f"edit_device_{device['id']}"):
                    edited_name = st.text_input("Device name", value=device["name"], max_chars=80)
                    edited_category = st.selectbox("Category", DEVICE_CATEGORIES,
                                                   index=DEVICE_CATEGORIES.index(device["category"]),
                                                   key=f"category_{device['id']}")
                    edited_room = st.text_input("Room", value=device["room"], max_chars=100)
                    if st.form_submit_button("Save device details"):
                        try:
                            save_device(edited_name, edited_category, edited_room,
                                        device["address"], device_id=device["id"])
                            st.success("Device details updated.")
                            st.rerun()
                        except ValueError as error:
                            st.error(str(error))
    else:
        st.info("No user-registered devices yet. Add one from Connect Device.")
    st.divider()
    devices = [
        ("📷", "Camera-01", "Smart Camera", "192.168.1.10"),
        ("🌡️", "Temperature-01", "Temperature Sensor", "192.168.1.11"),
        ("💡", "Smart-Light-01", "Smart Light", "192.168.1.12"),
        ("🏠", "Gateway-01", "IoT Gateway", "192.168.1.1")
    ]
    for icon, name, device_type, ip in devices:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.write(f"{icon} **{name}**")
        with col2:
            st.write(device_type)
        with col3:
            st.write(ip)
        with col4:
            st.write("Demo profile · not checked")
        st.divider()
# -------------------------------------------------
# CONNECT IOT DEVICE
# -------------------------------------------------
elif page == "🔌 Connect Device":
    st.title("🔌 Connect an IoT Device")
    st.markdown(
        "Add a virtual device for the demo, or review what is needed to connect a real device. "
        "You do not need to know networking terminology to get started."
    )
    st.info(
        "A device description starts as Registered. Reachable requires a real successful connection check; Monitored requires a verified traffic source. This prototype does not mark devices online just because they are registered."
    )
    st.subheader("Option 1 — Add a demo device")
    st.caption("Use this option to explore the interface without buying hardware or entering network details.")
    with st.form("add_demo_device_form", clear_on_submit=True):
        device_name = st.text_input("Give your device a name", placeholder="e.g. Living Room Camera")
        device_type = st.selectbox(
            "Choose the device type",
            list(DEVICE_CATEGORIES)
        )
        room = st.text_input("Where is it located? (optional)", placeholder="e.g. Living room")
        address = st.text_input("Optional local address (for your reference only)", max_chars=100)
        connection_method = st.selectbox("Registration method", ["Demonstration/simulated", "Manual registration"])
        submitted = st.form_submit_button("＋ Register device description", use_container_width=True)
        if submitted:
            clean_name = device_name.strip()
            if not clean_name:
                st.error("Please enter a name for your device.")
            else:
                try:
                    save_device(clean_name, device_type, room, address, connection_method=connection_method)
                    st.success("Device registered locally with status Registered. This did not check reachability or begin traffic monitoring.")
                except ValueError as error:
                    st.warning(str(error))
    st.divider()
    st.subheader("Option 2 — Connect a real device over the internet")
    st.write(
        "A real connection needs a supported way to send device or network data to this hosted app. "
        "The exact method depends on your device and router. The app does not discover devices "
        "automatically just because they are connected to Wi-Fi."
    )
    with st.expander("What will be needed for a real connection?"):
        st.markdown(
            "1. **Device or gateway support:** a device integration, router/gateway telemetry, or an approved traffic exporter.\n"
            "2. **A secure receiver:** a hosted API or message service that accepts the data.\n"
            "3. **Authentication:** a protected device token or account connection; never paste Wi-Fi passwords here.\n"
            "4. **A processing pipeline:** convert received data into supported features before running the model.\n"
            "5. **A connection status:** show the last successful data receipt and any errors."
        )
    st.warning(
        "Manual registration stores only descriptive details. This project does not yet implement a remote gateway receiver, authenticated cloud ingestion, router integration, active reachability test, or live capture. Never enter Wi-Fi passwords or API keys here."
    )
    st.subheader("Choose what the app can actually observe")
    st.markdown("- **Demonstration/simulated:** creates a labeled example record.\n- **Manual registration:** stores a device description only.\n- **Uploaded traffic capture:** the Live Monitoring page accepts supported feature CSVs and saved packet-window data; it does not prove that a registered device produced those records.\n- **Gateway integration:** only the existing local demonstration gateway writes its own request-rate log. A secured remote integration is not configured.\n- **Live capture:** unavailable until capture software, interface permissions, and a tested capture adapter are present.")
# -------------------------------------------------
# LIVE MONITORING
# -------------------------------------------------
elif page == "🔍 Live Monitoring":
    st.title("🔍 Live Network Monitoring")
    st.info("This page is a monitoring overview, not a live packet feed. Use the recorded-capture analysis and gateway event sections below to inspect the files available in this project.")
    col1, col2, col3 = st.columns(3)
    packet_file = PROJECT_DIR / "iot_simulator" / "data" / "processed" / "iot_packet_features.csv"
    packet_rows = 0
    if packet_file.exists():
        try:
            packet_rows = len(pd.read_csv(packet_file))
        except Exception:
            packet_rows = 0
    with col1:
        st.metric("Saved packet records", f"{packet_rows:,}" if packet_rows else "Not available")
    with col2:
        st.metric("Saved flow records", f"{len(flow_data):,}" if not flow_data.empty else "Not available")
    with col3:
        st.metric("Gateway raw records", f"{gateway_state['raw_events']:,}")
    st.subheader("Where to go next")
    st.markdown("- Open **Threats** to inspect the example alert.\n- Scroll to **Experimental IoT AI Detector** to classify a saved normal or suspicious capture.\n- Use **Gateway Security Event Monitor** to inspect rule-based event records.")
    st.subheader("Analyze a compatible CIC-IDS feature CSV")
    st.caption("The upload must contain all 70 named numeric model features. Compact IoT flow summaries cannot be converted reliably and are rejected.")
    uploaded_features = st.file_uploader("Choose a CIC-IDS feature CSV (up to 20 MB)", type=["csv"], key="model_feature_upload")
    if uploaded_features is not None:
        try:
            from security_services import read_model_csv
            feature_frame = read_model_csv(uploaded_features)
            if st.button("Analyze validated feature records", key="analyze_uploaded_features"):
                prediction_result = safe_predict_flows(feature_frame)
                if not prediction_result["ok"]:
                    st.error(f"Model analysis unavailable: {prediction_result['error']}")
                    st.stop()
                predicted = pd.DataFrame(prediction_result["rows"])
                st.dataframe(predicted, use_container_width=True, hide_index=True)
                st.caption(f"Model version: {prediction_result['model_version']} · {prediction_result['timestamp']}")
                attack_count = int((predicted["prediction"] == "ATTACK").sum())
                stored_count = min(attack_count, 50)
                from security_services import add_observation
                add_observation("uploaded CIC-IDS feature CSV", "model analysis",
                                f"Analyzed {len(predicted)} rows: {attack_count} ATTACK, {len(predicted) - attack_count} BENIGN",
                                {"model_version": prediction_result["model_version"]})
                if attack_count:
                    for row_index in predicted.index[predicted["prediction"] == "ATTACK"][:50]:
                        create_alert("Uploaded feature record", "uploaded CIC-IDS feature CSV",
                                     "Random Forest model", f"Input row {int(row_index) + 1} classified ATTACK",
                                     "Medium", "Exact named model features were supplied; model predicted ATTACK.",
                                     "A model classification is a review signal, not confirmation of compromise.",
                                     "Review the source and supporting network evidence before taking action.",
                                     prediction_result["model_version"])
                    st.info(f"Stored {stored_count} of {attack_count} ATTACK-labeled rows as review alerts (maximum 50 per upload). These are model predictions, not confirmed incidents.")
        except ValueError as error:
            st.error(str(error))
        except Exception as error:
            st.error(f"Model analysis unavailable: {error}")
# -------------------------------------------------
# THREATS
# -------------------------------------------------
elif page == "🚨 Threats":
    st.title("🚨 Security Alerts")
    st.caption("An alert is a reason to investigate, not proof that a device has been compromised.")
    if st.session_state.threat_detected:
        st.error("HIGH RISK THREAT DETECTED")
        st.write("### Device")
        st.write("📷 Camera-01")
        st.write("### Threat Type")
        st.write("Suspicious Network Behavior")
        st.write("### Detection Source")
        st.write("Gateway request-frequency rule")
        st.caption(
            "The gateway alert is rule-based. The AI model's current "
            "predictions are experimental and are not a verified confidence "
            "score for this event."
            )
        st.write("### Why was it flagged?")
        st.write("✓ Request frequency exceeded the gateway threshold.")
        st.write("✓ The gateway recorded unusually frequent requests.")
        st.write("✓ This alert is based on request counts, not AI classification.")
        st.divider()
        st.write("### Recommended Action")
        st.info(
            "1. Check Camera-01's recent request activity in the gateway logs. "
            "2. Verify whether the high request frequency is expected. "
            "3. Review the device and destination details before taking action. "
            "4. If the activity is unauthorized, restrict the device's network "
            "access and investigate further."
            )
    else:
        st.success("No example alert is active in this session.")
        st.write("You can create an example alert from **Overview** or inspect saved gateway events below.")
    saved_incidents = list_incidents(limit=10)
    if saved_incidents:
        st.subheader("Persisted incidents")
        st.dataframe(pd.DataFrame([{"Last seen": format_local_timestamp(item["last_seen"]),
                                   "Device": item["device_name"], "Severity": item["severity"],
                                   "Status": item["status"], "Source": item["source"],
                                   "Detections": item["occurrence_count"]} for item in saved_incidents]),
                     use_container_width=True, hide_index=True)
        st.button("Open incident history", on_click=navigate_to, args=("📜 Event History",), key="threats_history_cta")
# -------------------------------------------------
# EVENT HISTORY
# -------------------------------------------------
elif page == "📜 Event History":
    st.title("📜 Event History")
    render_incident_browser("history")
# -------------------------------------------------
# USER GUIDE
# -------------------------------------------------
elif page == "📘 User Guide":
    st.title("📘 How to Use AI-IoT Security Monitor")
    st.write(
        "Welcome! This guide explains how to navigate the application, "
        "review traffic analysis, and understand security alerts."
    )

    st.info(
        "Important: This is a college prototype. Some dashboard metrics are "
        "illustrative, some analysis uses recorded captures, and gateway "
        "alerts are rule-based. The app is not a fully integrated live "
        "network intrusion detection product."
    )

    st.subheader("Quick start (about 2 minutes)")
    st.markdown("1. Go to **Overview**.\n2. Click **Create example alert** to try the interface.\n3. Open **Threats** and read the explanation and recommended checks.\n4. Open **IoT Devices** to see the example device list.\n5. To test the experimental ML model, find **Advanced Tool: Experimental IoT AI Detector** further down this page and analyze a saved capture.")

    st.subheader("Getting started")
    st.markdown(
        "1. Open **Overview** to understand the project and see the main status.\n"
        "2. Open **IoT Devices** to view the example devices represented in the simulation.\n"
        "3. Open **Live Monitoring** to inspect the monitoring display. Check its labels: "
        "some values and activity entries are illustrative rather than live measurements.\n"
        "4. Open **Threats** to review a simulated alert and recommended investigation steps.\n"
        "5. Open **Event History** to review the event information currently available in the app."
    )

    st.subheader("How to analyze recorded IoT traffic")
    st.markdown(
        "1. Scroll down to **Experimental IoT AI Detector**.\n"
        "2. Select **Normal capture** or **Suspicious capture**.\n"
        "3. Click **Analyze Capture with IoT AI**.\n"
        "4. Review the number of windows classified as Normal or Suspicious, the results table, "
        "and the traffic explanation.\n"
        "5. Treat results as experimental: the model was trained using windows from the available "
        "captures, so these results are demonstrations, not independent real-world validation."
    )

    st.subheader("How to use the AI test")
    st.markdown(
        "Use **Run AI Prediction Test** to check that the trained Random Forest model can produce "
        "a prediction. This test uses artificial all-zero input; it does not analyze live traffic "
        "and its probability values should not be interpreted as a real security assessment."
    )

    st.subheader("What to do when an alert appears")
    st.markdown(
        "1. Check the device and timestamp shown in the event record.\n"
        "2. Verify whether the activity matches an update, restart, or authorized use.\n"
        "3. Review gateway logs and network destinations if available.\n"
        "4. If activity remains unexplained, ask the network administrator to investigate.\n"
        "5. Restrict network access only after confirming it is appropriate and safe to do so."
    )
    st.warning(
        "An alert indicates activity worth checking; it does not prove that a device has been hacked. "
        "A result classified as Normal does not guarantee that traffic is safe."
    )
    st.subheader("What this prototype does not do")
    st.markdown("- It does not automatically protect or block devices.\n- It does not currently provide a fully integrated, validated live-network detection pipeline.\n- Some device details are examples; recorded capture analyses use local files.\n- Do not treat experimental predictions as a guarantee of safety.")

elif page == "🧠 AI Security Assistant":
    st.title("🧠 AI Security Assistant")
    st.caption("Answers use read-only application records. Provider sharing occurs only when Gemini is configured.")
    try:
        configured_key = st.secrets.get("GEMINI_API_KEY")
    except Exception:
        configured_key = None
    gemini_status = gemini_config_status(configured_key)
    connection_test = st.session_state.get("gemini_connection_test")
    if not gemini_status["configured"]:
        connection_label = "Not configured"
    elif not gemini_status["sdk_available"]:
        connection_label = "Connection failed"
        connection_test = {"status": connection_label, "model": gemini_status["model"],
                           "message": "Google GenAI SDK is not installed."}
    elif connection_test and connection_test.get("model") == gemini_status["model"]:
        connection_label = connection_test["status"]
    else:
        connection_label = "Not tested"
    status_text = f"Gemini connection status: **{connection_label}** · Model: `{gemini_status['model']}`"
    if connection_label == "Connected":
        st.success(status_text + ". " + connection_test["message"])
    elif connection_label == "Connection failed":
        st.error(status_text + ". " + connection_test["message"])
    elif connection_label == "Not configured":
        st.info(status_text + ". The assistant is using local help mode.")
    else:
        st.info(status_text + ". A key is present; the API has not been tested.")
    if gemini_status["configured"] and gemini_status["sdk_available"]:
        if st.button("Test Gemini connection", key="test_gemini_connection"):
            with st.spinner("Sending one minimal test request to Gemini…"):
                st.session_state.gemini_connection_test = test_gemini_connection(api_key=configured_key)
            st.rerun()
    elif gemini_status["configured"]:
        st.caption("Install the project dependencies to enable the Google GenAI SDK. Local help remains available.")
    if "assistant_messages" not in st.session_state:
        st.session_state.assistant_messages = [{"role": "assistant", "content": "Hello! I can help explain recorded alerts, registered devices, model requirements, and what this prototype monitors."}]
    if st.button("Clear conversation"):
        st.session_state.assistant_messages = []
        st.rerun()
    for message in st.session_state.assistant_messages[-20:]:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    question = st.chat_input("Ask about an alert, device, model, or monitoring status…", max_chars=2000)
    if question:
        st.session_state.assistant_messages.append({"role": "user", "content": question})
        answer, provider = assistant_reply(question, app_context(), api_key=configured_key)
        if gemini_status["configured"]:
            if provider == "Gemini":
                st.session_state.gemini_connection_test = {
                    "status": "Connected", "model": gemini_status["model"],
                    "message": "Gemini successfully answered an assistant request.",
                }
            elif provider.startswith("local help fallback (Gemini"):
                st.session_state.gemini_connection_test = {
                    "status": "Connection failed", "model": gemini_status["model"],
                    "message": provider.removeprefix("local help fallback (").rstrip(")") + ".",
                }
        st.session_state.assistant_messages.append({"role": "assistant", "content": answer})
        st.session_state.assistant_messages = st.session_state.assistant_messages[-20:]
        st.caption(f"Response source: {provider}")
        st.rerun()
    st.caption("Try: What does my latest alert mean? · Is the app monitoring real traffic? · How do I register a device?")

elif page == "📄 Reports":
    st.title("📄 Incident Reports")
    st.write("Filter, investigate, and export the same persistent incidents shown in Event History.")
    render_incident_browser("reports", downloads=True)

elif page == "⚙️ Settings & Health":
    st.title("⚙️ Settings & System Health")
    st.write("**Active data source:** saved project files and local simulation. No live network capture is active.")
    st.write(f"**Persisted devices:** {len(list_devices())} · **Persisted incidents:** {incident_metrics()['total']}")
    model_state = model_diagnostics()
    st.write(f"**CIC-IDS Random Forest:** {'loaded' if model_state['available'] else 'unavailable'}")
    if model_state["available"]:
        st.write(f"**Model identity:** `{model_state['identity']}` · **Input features:** {model_state['feature_count']} · **Classes:** {', '.join(model_state['classes'])}")
        st.caption("Preprocessing found in the saved training code: numeric coercion, inf/NA to zero, duplicate/constant feature removal; no scaler or encoder artifact exists. Inference rejects incomplete rows and does not impute missing values.")
    else:
        st.warning(model_state["error"])
    st.write(f"**Database:** {gateway_state['incidents']:,} incidents, {gateway_state['raw_events']:,} raw gateway rows, {gateway_state['malformed_rows']:,} malformed rows reported on import.")
    try:
        configured_key = st.secrets.get("GEMINI_API_KEY")
    except Exception:
        configured_key = None
    gemini_status = gemini_config_status(configured_key)
    connection_test = st.session_state.get("gemini_connection_test")
    connection_label = ("Not configured" if not gemini_status["configured"] else
                        "Connection failed" if not gemini_status["sdk_available"] else
                        connection_test["status"] if connection_test and connection_test.get("model") == gemini_status["model"] else
                        "Not tested")
    if gemini_status["configured"] and gemini_status["sdk_available"]:
        st.write(f"**Gemini assistant:** {connection_label} · model `{gemini_status['model']}`")
    elif gemini_status["configured"]:
        st.warning("Gemini key is configured, but the SDK is not installed. Local help mode remains available.")
    else:
        st.write("**Gemini assistant:** no key detected · local help mode")
    st.info("For local Gemini use, set GEMINI_API_KEY in your environment. Do not paste credentials into the app. Cloud deployments should configure secrets and persistent database storage separately.")
    st.warning("This prototype does not enforce network controls. Upload and packet capture workflows need authorized data and the exact supported model schema.")

# -------------------------------------------------
if page == "🔍 Live Monitoring":
    # AI MODEL TEST
    # -------------------------------------------------
    st.divider()
    st.subheader("🧪 Advanced Tool: AI Model Smoke Test")
    st.write(
        "Test the trained model with artificial network features. "
        "This is a software test, not live network detection."
    )
    if model_loaded:
        if st.button("Run AI Prediction Test"):
            test_data = pd.DataFrame(
                [[0.0] * len(feature_columns)],
                columns=feature_columns
            )
            prediction = ai_model.predict(test_data)[0]
            probabilities = ai_model.predict_proba(test_data)[0]
            if prediction == 1:
                st.error("Model prediction: ATTACK")
            else:
                st.success("Model prediction: BENIGN")
            col1, col2 = st.columns(2)
            with col1:
                st.metric(
                    "BENIGN probability",
                    f"{probabilities[0] * 100:.2f}%"
                )
            with col2:
                st.metric(
                    "ATTACK probability",
                    f"{probabilities[1] * 100:.2f}%"
                )
            st.caption(
                "These probabilities are for artificial all-zero input. "
                "They do not establish whether actual network traffic is safe."
            )
    else:
        st.warning("The AI model is unavailable.")
    # -------------------------------------------------
    # IOT FLOW AI ANALYSIS
    # -------------------------------------------------
    st.divider()
    st.header("🤖 Advanced Tool: AI Analysis of IoT Network Flows")
    if not model_loaded:
        st.error("AI model is unavailable.")
    elif flow_data.empty:
        st.warning(
            "No flow data found. Generate and process network "
            "traffic first."
        )
    else:
        try:
            from iot_simulator.network.model_features import (
                convert_flows_for_model
            )
            model_input = convert_flows_for_model(FLOW_FILE)
            predictions = ai_model.predict(model_input)
            probabilities = ai_model.predict_proba(model_input)
            results = flow_data.copy()
            results["AI Prediction"] = [
                "ATTACK" if prediction == 1 else "BENIGN"
                for prediction in predictions
            ]
            results["Attack Probability (%)"] = (
                probabilities[:, 1] * 100
            ).round(2)
            benign_count = int((predictions == 0).sum())
            attack_count = int((predictions == 1).sum())
            col1, col2, col3 = st.columns(3)
            col1.metric("Flows Analysed", len(results))
            col2.metric("Predicted Benign", benign_count)
            col3.metric("Predicted Attacks", attack_count)
            st.subheader("Flow Prediction Results")
            st.dataframe(
                results,
                use_container_width=True,
                hide_index=True
            )
            st.caption(
                "Experimental predictions: the current flow features "
                "do not fully match the model's training features. "
                "These results are not validated real-world detections."
            )
        except ValueError as error:
            compatibility = flow_compatibility_report(flow_data)
            st.info("The saved IoT summary cannot be converted reliably to the primary CIC-IDS model input. "
                    f"It has {compatibility['flow_columns']} summary columns and {compatibility['exact_features_present']} exact model features; "
                    f"{compatibility['reliable_model_features_missing']} of {compatibility['model_features']} model features are unavailable. "
                    "No primary-model prediction was produced. The separate Experimental IoT AI Detector below is the available packet-window analysis path.")
            with st.expander("Why the saved summary is incompatible"):
                st.write("Available summary concepts: " + (", ".join(compatibility["summary_fields_present"]) or "none recognized"))
                for group_name, examples in compatibility["missing_groups"].items():
                    st.write(f"**Missing {group_name}:** " + ", ".join(examples))
        except Exception as error:
            st.error(f"AI flow analysis failed: {error}")
    # -------------------------------------------------
    # PERSISTED GATEWAY INCIDENT MONITOR
    # -------------------------------------------------
    st.divider()
    st.header("🚨 Gateway Incidents and Evidence")
    if st.button("🔄 Refresh saved gateway history"):
        sync_gateway_history.clear()
        if EVENT_FILE.exists():
            current_stat = EVENT_FILE.stat()
            sync_gateway_history(str(EVENT_FILE), current_stat.st_mtime_ns, current_stat.st_size)
        gateway_state = gateway_metrics()
        st.rerun()
    g1, g2, g3, g4 = st.columns(4)
    g1.metric("Raw log entries", f"{gateway_state['raw_events']:,}")
    g2.metric("Unique detections", f"{gateway_state['unique_detections']:,}")
    g3.metric("Incidents", f"{gateway_state['incidents']:,}")
    g4.metric("Unresolved", f"{gateway_state['unresolved_incidents']:,}")
    st.caption("The gateway rule detects unusual request rates. It does not establish that an attack occurred or that traffic was blocked.")
    render_incident_browser("gateway_live")
    # -------------------------------------------------
    # NORMAL VS SUSPICIOUS CAPTURE COMPARISON
    # -------------------------------------------------
    st.divider()
    st.header("📈 Recorded Traffic Comparison")
    PROCESSED_DIR = (
        PROJECT_DIR
        / "iot_simulator"
        / "data"
        / "processed"
    )
    normal_file = PROCESSED_DIR / "normal_packet_features.csv"
    suspicious_file = PROCESSED_DIR / "suspicious_packet_features.csv"
    def get_capture_summary(file_path, scenario):
        if not file_path.exists():
            return None
        data = pd.read_csv(file_path)
        if data.empty or "timestamp" not in data.columns:
            return None
        duration = data["timestamp"].max() - data["timestamp"].min()
        if duration <= 0:
            return None
        return {
            "Scenario": scenario,
            "IPv4 packets": len(data),
            "Duration (seconds)": round(duration, 2),
            "Packets per second": round(len(data) / duration, 2),
        }
    normal_summary = get_capture_summary(normal_file, "Normal")
    suspicious_summary = get_capture_summary(
        suspicious_file, "Suspicious"
    )
    if normal_summary and suspicious_summary:
        comparison = pd.DataFrame(
            [normal_summary, suspicious_summary]
        )
        normal_rate = normal_summary["Packets per second"]
        suspicious_rate = suspicious_summary["Packets per second"]
        col1, col2, col3 = st.columns(3)
        col1.metric("Normal traffic", f"{normal_rate:.2f} packets/sec")
        col2.metric(
            "Suspicious capture",
            f"{suspicious_rate:.2f} packets/sec"
        )
        ratio = suspicious_rate / normal_rate if normal_rate > 0 else 0
        col3.metric("Rate ratio", f"{ratio:.2f}x")
        st.dataframe(
            comparison,
            use_container_width=True,
            hide_index=True
        )
        st.bar_chart(
            comparison.set_index("Scenario")[["Packets per second"]]
        )
        st.caption(
            "This compares previously recorded captures, not live traffic. "
            "A high packet rate indicates unusual volume but does not alone "
            "prove malicious activity."
        )
    else:
        st.info(
            "Capture comparison is unavailable. Run feature_extraction.py "
            "for both normal and suspicious captures first."
        )

    # -------------------------------------------------
    # EXPERIMENTAL IOT AI DETECTOR
    # -------------------------------------------------

    def explain_iot_window(row, normal_baseline):
        """Explain observed traffic patterns, not the cause of an attack."""

        explanations = []

        normal_rate = normal_baseline["packets_per_second"].mean()
        normal_bytes = normal_baseline["bytes_per_second"].mean()
        normal_size = normal_baseline["average_packet_size"].mean()
        normal_std = normal_baseline["packet_size_std"].mean()

        if normal_rate > 0 and row["packets_per_second"] > normal_rate * 2:
            explanations.append(
                f"High packet rate: {row['packets_per_second']:.1f} packets/sec, "
                f"over 2x the normal-capture average ({normal_rate:.1f})."
            )

        if normal_bytes > 0 and row["bytes_per_second"] > normal_bytes * 2:
            explanations.append(
                f"High traffic volume: {row['bytes_per_second']:.1f} bytes/sec, "
                f"over 2x the normal-capture average ({normal_bytes:.1f})."
            )

        if normal_size > 0 and row["average_packet_size"] > normal_size * 1.5:
            explanations.append(
                "Average packet size is substantially larger than the "
                "normal-capture average."
            )

        if normal_size > 0 and row["average_packet_size"] < normal_size * 0.5:
            explanations.append(
                "Average packet size is substantially smaller than the "
                "normal-capture average."
            )

        if row["packet_size_std"] > normal_std * 2:
            explanations.append(
                "Packet sizes vary more than in the normal capture."
            )

        if not explanations:
            explanations.append(
                "No configured traffic measurement exceeded the comparison "
                "thresholds. This does not guarantee safety."
            )

        return " ".join(explanations)


    st.divider()
    st.header("🤖 Advanced Tool: Experimental IoT AI Detector")

    st.write(
        "This separate machine-learning model analyzes packet-level "
        "traffic patterns in previously recorded IoT captures."
    )

    if not iot_detector_loaded:
        st.error("The experimental IoT detector could not be loaded.")

    else:
        st.warning(
            "Prototype limitation: this model was trained using windows from "
            "the available normal and suspicious captures. Results on these "
            "same captures are demonstration results, not independent "
            "real-world accuracy."
        )

        scenario_options = {
            "Normal capture": (
                PROCESSED_DIR / "normal_packet_features.csv"
            ),
            "Suspicious capture": (
                PROCESSED_DIR / "suspicious_packet_features.csv"
            ),
        }

        selected_scenario = st.selectbox(
            "Choose a recorded traffic capture",
            list(scenario_options.keys()),
            key="iot_detector_scenario",
        )

        if st.button(
            "Analyze Capture with IoT AI",
            key="run_iot_detector",
        ):
            selected_file = scenario_options[selected_scenario]

            if not selected_file.exists():
                st.error(f"Capture file not found: {selected_file.name}")

            else:
                try:
                    packets = pd.read_csv(selected_file)

                    required_columns = [
                        "timestamp",
                        "packet_length_bytes",
                        "protocol",
                    ]

                    missing = [
                        column for column in required_columns
                        if column not in packets.columns
                    ]

                    if missing:
                        st.error(
                            "Capture is missing required columns: "
                            + ", ".join(missing)
                        )

                    elif packets.empty:
                        st.error("The selected capture contains no packets.")

                    else:
                        packets["timestamp"] = pd.to_numeric(
                            packets["timestamp"], errors="coerce"
                        )
                        packets["packet_length_bytes"] = pd.to_numeric(
                            packets["packet_length_bytes"],
                            errors="coerce",
                        )

                        packets = packets.dropna(
                            subset=["timestamp", "packet_length_bytes"]
                        ).sort_values("timestamp")

                        if packets.empty:
                            st.error("No valid packet records were found.")

                        else:
                            packets["window"] = (
                                (
                                    packets["timestamp"]
                                    - packets["timestamp"].min()
                                ) // iot_window_seconds
                            ).astype(int)

                            def build_window_features(packet_data):
                                rows = []

                                for _, group in packet_data.groupby("window"):
                                    lengths = group["packet_length_bytes"]

                                    rows.append({
                                        "packets_per_second": (
                                            len(group) / iot_window_seconds
                                        ),
                                        "bytes_per_second": (
                                            lengths.sum() / iot_window_seconds
                                        ),
                                        "average_packet_size": lengths.mean(),
                                        "maximum_packet_size": lengths.max(),
                                        "packet_size_std": (
                                            lengths.std()
                                            if len(group) > 1 else 0
                                        ),
                                        "tcp_ratio": (
                                            group["protocol"]
                                            .astype(str)
                                            .str.upper()
                                            .eq("TCP")
                                            .mean()
                                        ),
                                    })

                                return pd.DataFrame(rows)

                            model_input = build_window_features(packets)
                            model_input = model_input[
                                iot_detector_features
                            ]

                            predictions = iot_detector.predict(model_input)

                            results = model_input.copy()
                            results["AI Prediction"] = [
                                "Suspicious" if value == 1 else "Normal"
                                for value in predictions
                            ]

                            # Build the baseline from the recorded normal capture.
                            baseline_file = (
                                PROCESSED_DIR / "normal_packet_features.csv"
                            )

                            normal_baseline_features = None

                            if baseline_file.exists():
                                baseline_packets = pd.read_csv(baseline_file)

                                baseline_packets["timestamp"] = pd.to_numeric(
                                    baseline_packets["timestamp"],
                                    errors="coerce",
                                )
                                baseline_packets["packet_length_bytes"] = (
                                    pd.to_numeric(
                                        baseline_packets["packet_length_bytes"],
                                        errors="coerce",
                                    )
                                )

                                baseline_packets = baseline_packets.dropna(
                                    subset=[
                                        "timestamp",
                                        "packet_length_bytes",
                                    ]
                                ).sort_values("timestamp")

                                if not baseline_packets.empty:
                                    baseline_packets["window"] = (
                                        (
                                            baseline_packets["timestamp"]
                                            - baseline_packets["timestamp"].min()
                                        ) // iot_window_seconds
                                    ).astype(int)

                                    normal_baseline_features = (
                                        build_window_features(baseline_packets)
                                    )

                            if normal_baseline_features is not None:
                                results["Traffic Explanation"] = results.apply(
                                    lambda row: explain_iot_window(
                                        row, normal_baseline_features
                                    ),
                                    axis=1,
                                )
                            else:
                                results["Traffic Explanation"] = (
                                    "Normal-capture baseline unavailable; "
                                    "comparison could not be performed."
                                )

                            normal_count = int((predictions == 0).sum())
                            suspicious_count = int((predictions == 1).sum())

                            col1, col2, col3 = st.columns(3)

                            col1.metric("Windows Analyzed", len(results))
                            col2.metric("Predicted Normal", normal_count)
                            col3.metric(
                                "Predicted Suspicious", suspicious_count
                            )

                            st.subheader("AI Prediction Results")

                            st.dataframe(
                                results.round(2),
                                use_container_width=True,
                                hide_index=True,
                            )

                            st.subheader("Prediction Summary")

                            st.bar_chart(
                                results["AI Prediction"]
                                .value_counts()
                                .reindex(
                                    ["Normal", "Suspicious"],
                                    fill_value=0,
                                )
                            )

                            if suspicious_count > 0:
                                st.warning(
                                    f"The model classified {suspicious_count} "
                                    "window(s) as suspicious. Review the traffic "
                                    "measurements before taking action."
                                )
                            else:
                                st.success(
                                    "No windows were classified as suspicious. "
                                    "This does not guarantee that the traffic "
                                    "is safe."
                                )

                            st.caption(
                                "Traffic explanations compare measured features "
                                "with the recorded normal capture. They are "
                                "heuristic comparisons, not proof of malicious "
                                "activity or the model's internal reasoning. "
                                "Validate using separate captures."
                            )

                except Exception as error:
                    st.error(f"IoT AI analysis failed: {error}")
