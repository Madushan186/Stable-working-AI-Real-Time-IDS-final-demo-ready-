import streamlit as st
import json
import pandas as pd
import time
import os
import plotly.express as px
import plotly.graph_objects as go

# -----------------------
# PAGE CONFIGURATION
# -----------------------
st.set_page_config(
    page_title="SecureNet AI | Enterprise SOC",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------
# CUSTOM CSS (ENTERPRISE SOC THEME)
# -----------------------
st.markdown("""
<style>
    /* Main Background & Font */
    .stApp {
        background-color: #0d1117;
        font-family: 'SF Pro Display', sans-serif;
    }
    
    /* Metrics Cards */
    div[dataset-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        transition: transform 0.2s;
    }
    div[dataset-testid="stMetric"]:hover {
        transform: translateY(-2px);
        border-color: #58a6ff;
    }
    div[dataset-testid="stMetricLabel"] {
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8b949e;
    }
    div[dataset-testid="stMetricValue"] {
        font-size: 28px;
        font-weight: 700;
        color: #f0f6fc;
    }

    /* Status Banner */
    .status-container {
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 25px;
        text-align: center;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    .status-secure {
        background: linear-gradient(90deg, rgba(35,134,54,0.15) 0%, rgba(35,134,54,0.05) 100%);
        border: 1px solid #238636;
        color: #3fb950;
    }
    .status-critical {
        background: linear-gradient(90deg, rgba(218,54,51,0.25) 0%, rgba(218,54,51,0.1) 100%);
        border: 1px solid #da3633;
        color: #f85149;
        animation: pulse-red 2s infinite;
    }
    
    /* Animations */
    @keyframes pulse-red {
        0% { box-shadow: 0 0 0 0 rgba(218, 54, 51, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(218, 54, 51, 0); }
        100% { box-shadow: 0 0 0 0 rgba(218, 54, 51, 0); }
    }

    /* Headers */
    h1, h2, h3 {
        color: #e6edf3 !important;
        font-weight: 600;
    }
    .sub-header {
        font-size: 14px;
        color: #8b949e;
        margin-bottom: 10px;
    }

    /* DataFrame / Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid #30363d;
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

STATE_FILE = "ids_state.json"
LOG_FILE = "attack_log.csv"

# -----------------------
# DATA LOADING
# -----------------------
def read_state():
    if not os.path.exists(STATE_FILE):
        return {"total": 0, "attacks": 0, "status": "Normal"}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {"total": 0, "attacks": 0, "status": "Normal"}

def read_logs():
    if not os.path.exists(LOG_FILE):
        # Return empty with correct columns
        return pd.DataFrame(columns=["timestamp", "attack_type", "severity", "confidence", "rate", "monitor_source"])
    try:
        df = pd.read_csv(LOG_FILE)
        
        # Backward Compatibility: Ensure all columns exist
        required_columns = ["timestamp", "attack_type", "severity", "confidence", "rate", "monitor_source"]
        for col in required_columns:
            if col not in df.columns:
                df[col] = "N/A" # Fill missing with default
                
        df = df.iloc[::-1] # Newest first
        return df
    except:
        return pd.DataFrame(columns=["timestamp", "attack_type", "severity", "confidence", "rate", "monitor_source"])


# -----------------------
# SIDEBAR
# -----------------------
with st.sidebar:
    st.markdown("### SecureNet Node-1")
    st.markdown("---")
    
    # Status Indicator Widget
    state = read_state()
    # No icon for status
    status_text = "NORMAL" if state["status"] == "Normal" else "AFFECTED"
    
    st.markdown(f"**System Status**: {status_text} - {state['status'].upper()}")
    
    st.markdown("### Detection Engine")
    st.info("Hybrid AI Mode Active")
    st.markdown("""
    <div style='font-size: 12px; color: #8b949e;'>
    <b>1. RANDOM FOREST</b> (Supervised)<br>
    <i>Detects known attack patterns</i><br><br>
    <b>2. ISOLATION FOREST</b> (Unsupervised)<br>
    <i>Detects zero-day anomalies</i><br><br>
    <b>3. TRAFFIC RULES</b> (Volumetric)<br>
    <i>Detects DoS/Floods immediately</i>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### Configuration")
    st.code("""
Interface: en0
Threshold: 20 r/s
Model: RF + IF
    """, language="yaml")
    
    st.divider()
    st.caption("v3.0.0 Hybrid AI Build")
    st.caption("Developed by Lakshitha Madushan")

# -----------------------
# MAIN LAYOUT
# -----------------------

# 1. Top Bar
c1, c2 = st.columns([0.8, 4])
with c1:
    st.markdown("## SOC")
with c2:
    st.markdown("## Enterprise Threat Monitor")
    st.markdown("<div class='sub-header'>Hybrid AI-Powered Network Intelligence System</div>", unsafe_allow_html=True)

st.divider()

state = read_state()
logs = read_logs()

# 2. Hero Status Banner
if state["status"] == "ATTACK":
    st.markdown("""
        <div class="status-container status-critical">
            SECURITY ALERT: ACTIVE INTRUSION DETECTED
        </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
        <div class="status-container status-secure">
            SYSTEM SECURE: HYBRID MONITORING ACTIVE
        </div>
    """, unsafe_allow_html=True)

# 3. High-Level Metrics (KPIs)
kpi1, kpi2, kpi3, kpi4 = st.columns(4)

with kpi1:
    st.metric("Packets Analyzed", f"{state['total']:,}", delta="Live", delta_color="off")
with kpi2:
    st.metric("Threats Mitigated", state['attacks'], delta="Cumulative", delta_color="inverse")
with kpi3:
    peak = logs["rate"].max() if not logs.empty else 0
    current_rate = logs.iloc[0]["rate"] if not logs.empty else 0
    st.metric("Current Load", f"{current_rate:.1f} r/s", delta=f"Peak: {peak:.1f}")
with kpi4:
    # Most recent detection source
    source = logs.iloc[0]["monitor_source"] if not logs.empty else "System"
    st.metric("Active Logic", source, delta="Engine")

st.markdown("---")

# 4. Visualization & Alerts
col_chart, col_table = st.columns([1.8, 1.2])

with col_chart:
    st.markdown("### Traffic Velocity Analysis")
    if not logs.empty:
        chart_data = logs.iloc[:50].iloc[::-1] # Last 50 points, chronological
        
        # Professional Area Chart
        fig = px.area(
            chart_data,
            x="timestamp",
            y="rate",
            labels={"rate": "Packets / Sec", "timestamp": "Timeline"},
            color_discrete_sequence=["#58a6ff"]
        )
        
        # Style Chart to match SOC theme
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#8b949e"),
            margin=dict(l=20, r=20, t=10, b=20),
            height=320,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#30363d")
        )
        # Add red gradient for attacks
        fig.update_traces(
            line=dict(width=2),
            fillcolor="rgba(88, 166, 255, 0.1)"
        )
        
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("System initializing... waiting for traffic stream.")

with col_table:
    st.markdown("### Threat Ledger")
    if not logs.empty:
        # Fancy table Config
        st.dataframe(
            logs[["timestamp", "attack_type", "severity", "confidence", "monitor_source"]].head(8),
            hide_index=True,
            use_container_width=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Time", width="medium"),
                "attack_type": st.column_config.TextColumn("Signature", width="medium"),
                "severity": st.column_config.TextColumn("Sev", width="small"),
                "confidence": st.column_config.TextColumn("Conf", width="small"),
                "monitor_source": st.column_config.TextColumn("Source", width="medium"),
            }
        )
    else:
        st.markdown("<div style='text-align: center; color: #8b949e; padding: 20px;'>No security incidents recorded.</div>", unsafe_allow_html=True)

# 5. Footer
st.markdown("---")
f1, f2 = st.columns([1, 1])
with f1:
    st.markdown(f"<div style='color: #8b949e; font-size: 12px;'>System Uptime: {time.strftime('%H:%M:%S')} UTC</div>", unsafe_allow_html=True)
with f2:
    st.markdown("<div style='color: #8b949e; font-size: 12px; text-align: right;'>SecureNet AI v3.0 | Hybrid Architecture</div>", unsafe_allow_html=True)

# Auto-Refresh
time.sleep(1)
st.rerun()

