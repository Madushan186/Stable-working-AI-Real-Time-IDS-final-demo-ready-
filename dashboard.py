import streamlit as st
import time
import json
import os

st.set_page_config(page_title="AI IDS Dashboard", layout="wide")
st.title("🚨 AI-Based Real-Time Intrusion Detection System")

STATE_FILE = "ids_state.json"

def read_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {"total": 0, "attacks": 0, "status": "Normal"}
            
placeholder = st.empty()

while True:
    state = read_state()

    with placeholder.container():
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total Traffic", state["total"])

        with col2:
            st.metric("Attacks Detected", state["attacks"])

        if state["status"] == "ATTACK":
            st.error("🚨 ATTACK DETECTED")
        else:
            st.success("Normal traffic")

    time.sleep(1)
