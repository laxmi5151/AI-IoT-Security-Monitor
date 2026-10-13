import time
from datetime import datetime

import pandas as pd
import streamlit as st

# ------------------------------------------------------------
# AI-IoT Security Monitor — Presentation Demo Screen
# This is a presentation mock. Metrics/events are simulated and
# clearly labelled; it does not monitor live network traffic.
# ------------------------------------------------------------

st.set_page_config(
    page_title="Sentinel | IoT Security Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
      .stApp { background: #0a1020; color: #edf2ff; }
      [data-testid="stHeader"] { background: rgba(10,16,32,0.9); }
      [data-testid="stSidebar"] { background: #101a30; }
      .block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1500px; }
      h1, h2, h3, p, label { color: #edf2ff; }
      .eyebrow { color:#7dd3fc; text-transform:uppercase; letter-spacing:2px; font-size:0.75rem; font-weight:700; }
      .hero { padding: 1.35rem 1.5rem; border:1px solid #263653; border-radius:18px;
              background:linear-gradient(120deg,#14233d,#10182b 65%,#16253a); margin-bottom:1rem; }
      .hero-title { font-size:2rem; line-height:1.15; font-weight:800; margin:0.25rem 0; color:#f8fbff; }
      .muted { color:#a8b7d3; font-size:0.92rem; }
      .pill { display:inline-block; border:1px solid #355070; background:#172b46; color:#bae6fd;
              border-radius:999px; padding:0.25rem 0.65rem; font-size:0.75rem; margin-right:0.35rem; }
      .panel { border:1px solid #263653; background:#111b2f; border-radius:16px; padding:1rem 1.1rem; }
      .device { border:1px solid #293b59; background:#111b2f; border-radius:14px; padding:0.85rem; min-height:118px; }
      .device-icon { font-size:1.55rem; }
      .device-name { font-weight:700; font-size:1rem; color:#f8fbff; margin-top:0.25rem; }
      .small { color:#9fb0cc; font-size:0.8rem; }
      .status-good { color:#86efac; font-weight:700; }
      .status-warn { color:#fbbf24; font-weight:700; }
      .status-bad { color:#fca5a5; font-weight:700; }
      .metric-label { color:#9fb0cc; font-size:0.82rem; }
      .metric-value { color:#f8fbff; font-size:1.75rem; font-weight:800; }
      .callout { border-radius:12px; padding:0.85rem 1rem; background:#182641; border:1px solid #304765; }
      div[data-testid="stMetric"] { background:#111b2f; border:1px solid #263653; border-radius:14px; padding:0.8rem 1rem; }
      div[data-testid="stMetricLabel"] { color:#a8b7d3; }
      div[data-testid="stMetricValue"] { color:#f8fbff; }
      .footer { color:#8496b5; font-size:0.75rem; border-top:1px solid #263653; padding-top:0.9rem; }
      .stButton > button { border-radius:10px; font-weight:700; min-height:2.7rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "scenario" not in st.session_state:
    st.session_state.scenario = "Normal operation"
if "event_log" not in st.session_state:
    st.session_state.event_log = []
if "demo_started" not in st.session_state:
    st.session_state.demo_started = False

def set_scenario(name):
    st.session_state.scenario = name
    st.session_state.demo_started = True
    stamp = datetime.now().strftime("%H:%M:%S")
    if name == "Suspicious activity":
        message = "Camera-01 request rate exceeded the demo gateway threshold."
        severity = "HIGH"
    else:
        message = "Normal device activity restored in the demonstration."
        severity = "INFO"
    st.session_state.event_log.insert(0, {"Time": stamp, "Severity": severity, "Event": message})
    st.session_state.event_log = st.session_state.event_log[:8]

suspicious = st.session_state.scenario == "Suspicious activity"
packet_rate = 152.3 if suspicious else 20.1
bytes_rate = 10470 if suspicious else 2618
requests = 11 if suspicious else 1
ai_label = "Suspicious pattern" if suspicious else "Normal pattern"
ai_status = "⚠️ REVIEW RECOMMENDED" if suspicious else "✓ NO ANOMALY IN DEMO"
risk_text = "Elevated" if suspicious else "Low"
risk_delta = "Above demo baseline" if suspicious else "Within demo baseline"

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Sentinel • IoT Network Protection</div>
      <div class="hero-title">AI-IoT Security Monitor</div>
      <p class="muted">A guided demonstration of simulated IoT traffic, gateway rules, and experimental ML classification.</p>
      <span class="pill">PRESENTATION MODE</span><span class="pill">SIMULATED METRICS</span><span class="pill">NO LIVE NETWORK ACCESS</span>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([1.6, 1], gap="large")
with left:
    st.subheader("Environment overview")
    d1, d2, d3, d4 = st.columns(4)
    for col, icon, name, address, state in [
        (d1, "📷", "Camera-01", "192.168.1.10", "Suspicious" if suspicious else "Online"),
        (d2, "💡", "Smart-Light", "192.168.1.12", "Online"),
        (d3, "🌡️", "Temp-Sensor", "192.168.1.11", "Online"),
        (d4, "🛡️", "Gateway-01", "192.168.1.1", "Alert" if suspicious else "Online"),
    ]:
        with col:
            st.markdown(
                f"""<div class="device"><div class="device-icon">{icon}</div>
                <div class="device-name">{name}</div><div class="small">{address}</div>
                <div class="{'status-bad' if state == 'Suspicious' else 'status-warn' if state == 'Alert' else 'status-good'}">{state}</div></div>""",
                unsafe_allow_html=True,
            )
    st.write("")
    st.subheader("Traffic telemetry")
    m1, m2, m3 = st.columns(3)
    m1.metric("Packets / second", f"{packet_rate:.1f}", "7.6× vs normal demo" if suspicious else "Normal demo baseline")
    m2.metric("Bytes / second", f"{bytes_rate:,}", "Increased volume" if suspicious else "Within demo baseline")
    m3.metric("Requests in 2-sec window", str(requests), "Threshold exceeded" if suspicious else "Below alert threshold")
    chart_df = pd.DataFrame({
        "Time window": list(range(1, 13)),
        "Normal baseline": [19, 20, 18, 21, 20, 22, 19, 21, 20, 19, 20, 21],
        "Current demo traffic": (
            [20, 19, 21, 20, 22, 21, 19, 150, 155, 148, 158, 152]
            if suspicious else [20, 19, 21, 20, 22, 21, 19, 20, 18, 21, 20, 20]
        ),
    }).set_index("Time window")
    st.line_chart(chart_df, height=250)
    st.caption("Illustrative telemetry for the presentation mock. It is not a live packet feed.")

with right:
    st.subheader("Run the scenario")
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("**Choose what the audience sees**")
    st.write("Start with normal traffic, then trigger the suspicious-activity scenario.")
    a, b = st.columns(2)
    with a:
        if st.button("▶ Normal", use_container_width=True):
            set_scenario("Normal operation")
            st.rerun()
    with b:
        if st.button("⚠ Trigger alert", type="primary", use_container_width=True):
            set_scenario("Suspicious activity")
            st.rerun()
    if st.button("↺ Reset demo", use_container_width=True):
        st.session_state.scenario = "Normal operation"
        st.session_state.event_log = []
        st.session_state.demo_started = False
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")
    st.subheader("Detection outcome")
    if suspicious:
        st.error("Gateway rule alert: unusually frequent requests")
        st.markdown("**Experimental ML display:** " + ai_label)
        st.markdown("**Recommended response:**")
        st.write("1. Review Camera-01 request activity.")
        st.write("2. Confirm whether the traffic is expected.")
        st.write("3. If unauthorized, restrict device access and investigate.")
    else:
        st.success("Gateway rule: no request-rate alert in this demo")
        st.markdown("**Experimental ML display:** " + ai_label)
        st.write("Traffic measurements remain near the normal demonstration baseline.")
    st.caption("The screen illustrates the expected workflow. Actual model predictions in the project are run on recorded captures, not on this mock's synthetic telemetry.")

st.divider()
bottom_left, bottom_right = st.columns([1.15, 1], gap="large")
with bottom_left:
    st.subheader("Detection workflow")
    st.markdown(
        """
        <div class="panel">
          <span class="pill">01 · Simulated devices</span> → 
          <span class="pill">02 · Traffic features</span> → 
          <span class="pill">03 · Gateway rule + ML</span> → 
          <span class="pill">04 · Dashboard alert</span>
          <p class="muted" style="margin-top:0.9rem">The gateway request-frequency rule and the machine-learning detector are separate components. The AI detector currently analyzes recorded captures when manually run.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with bottom_right:
    st.subheader("Event timeline")
    if st.session_state.event_log:
        st.dataframe(pd.DataFrame(st.session_state.event_log), use_container_width=True, hide_index=True)
    else:
        st.info("No demo events yet. Trigger the alert to add an event to this timeline.")

st.markdown(
    '<div class="footer">College project demonstration • Synthetic display values • Not a production security tool • Validate ML performance on independent captures before real-world use</div>',
    unsafe_allow_html=True,
)
