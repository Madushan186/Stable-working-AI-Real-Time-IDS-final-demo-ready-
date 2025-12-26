import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, TCP, UDP, ICMP
from collections import deque
import datetime

# ==========================================
# FINAL YEAR PROJECT: AI-BASED REAL-TIME IDS
# ==========================================
# Author: Lakshitha Madushan
# Component: Packet Capture & Detection Engine
# Description: Captures live traffic, extracts features, and applies Hybrid Detection (Rules + ML).

# --- CONFIGURATION ---
MODEL_PATH = "models/rf_ids_model.pkl"
STATE_FILE = "ids_state.json"
LOG_FILE = "attack_log.csv"
HTTP_FLOOD_THRESHOLD = 20  # Requests per second to trigger alert (Rule-based)
COOLDOWN_DURATION = 3.0    # Stability mechanism to prevent alert flickering

# --- GLOBAL STATE ---
# Sliding Window for Rate Calculation
# deque is used for O(1) appends and pops, crucial for real-time performance.
packet_times = deque(maxlen=100)
http_requests = deque(maxlen=200)

# State management variables
current_status = "Normal"
last_attack_time = 0.0
total_packets = 0
total_attacks = 0

# Load trained Machine Learning Model (Random Forest)
try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ [INIT] Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    print(f"⚠️ [INIT] Error loading model: {e}")
    model = None

start_time = time.time()

# 41 Features used in CICIDS2017 Dataset
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

def log_attack(attack_type, rate):
    """
    Logs detected attacks to a CSV file for auditing and dashboard visualization.
    Format: timestamp, attack_type, rate
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize file with headers if missing
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("timestamp,attack_type,rate\n")
            
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp},{attack_type},{rate:.2f}\n")

def update_state_file(status, total, attacks):
    """
    Updates the system state JSON file atomically.
    Atomic Write: Writes to a .tmp file first, then renames it.
    This prevents the Dashboard from reading a corrupt/half-written file.
    """
    state = {
        "total": total,
        "attacks": attacks,
        "status": status
    }
    
    tmp_file = f"{STATE_FILE}.tmp"
    try:
        with open(tmp_file, "w") as f:
            json.dump(state, f)
        os.replace(tmp_file, STATE_FILE)
    except Exception as e:
        print(f"Error updating state: {e}")

def extract_features(packet):
    """
    Extracts 41 features from a raw packet to match the Random Forest model input.
    Note: Real-time extraction is simplified compared to offline dataset generation.
    """
    duration = time.time() - start_time
    
    # Protocol encoding: 1=TCP, 2=UDP, 3=ICMP
    if TCP in packet:
        protocol = 1
    elif UDP in packet:
        protocol = 2
    elif ICMP in packet:
        protocol = 3
    else:
        protocol = 0

    src_bytes = len(packet)
    dst_bytes = len(packet)

    # Initialize feature vector
    features = np.zeros(41)
    features[0] = duration
    features[1] = protocol
    features[4] = src_bytes
    features[5] = dst_bytes
    features[22] = total_packets # Approximation for 'count' feature
    features[23] = total_packets 

    # Reshape for Scikit-Learn (1 row, N columns)
    df = pd.DataFrame(features.reshape(1, -1), columns=columns)
    return df

def packet_handler(packet):
    """
    Main Callback Function triggered for every captured packet.
    Implements the Hybrid Detection Logic.
    """
    global total_packets, total_attacks, current_status, last_attack_time

    now = time.time()
    total_packets += 1
    packet_times.append(now)

    # ---------------------------
    # 1. TRAFFIC ANALYSIS (RULES)
    # ---------------------------
    is_http = False
    if TCP in packet and packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80 or packet[TCP].dport == 8080 or packet[TCP].sport == 8080:
             is_http = True
             http_requests.append(now)

    # Rate Calculation (Packets/Sec)
    packet_rate = 0
    if len(packet_times) > 1:
        duration = packet_times[-1] - packet_times[0]
        if duration > 0:
            packet_rate = len(packet_times) / duration

    # HTTP Rate Calculation
    http_rate = 0
    if len(http_requests) > 1:
        # Filter requests from last 1.0 second (Sliding Window)
        valid_requests = [t for t in http_requests if now - t <= 1.0]
        http_rate = len(valid_requests)
    
    # ---------------------------
    # 2. DETECTION LOGIC (HYBRID)
    # ---------------------------
    attack_detected = False
    attack_type = ""
    
    # RULE 1: Volumetric Analysis (HTTP Flood)
    if http_rate > HTTP_FLOOD_THRESHOLD:
        attack_detected = True
        attack_type = "HTTP Flood (DoS)"
        print(f"🚨 [RULE] HTTP FLOOD DETECTED! Rate: {http_rate} req/s")

    # RULE 2: Machine Learning Analysis (Anomaly)
    # Applied if no obvious accumulation rule is triggered, or in parallel
    elif model is not None:
        try:
            features = extract_features(packet)
            prediction = model.predict(features)[0]
            if prediction == "attack": 
                attack_detected = True
                attack_type = "ML Anomaly Pattern"
                print("🚨 [ML] ANOMALY DETECTED BY RANDOM FOREST")
        except Exception:
            pass 

    # ---------------------------
    # 3. STATE MACHINE & LOGGING
    # ---------------------------
    if attack_detected:
        last_attack_time = now
        if current_status != "ATTACK":
            current_status = "ATTACK"
            total_attacks += 1
            log_attack(attack_type, max(http_rate, packet_rate))
    
    else:
        # Cooldown Logic: Prevents "flickering" of status
        if current_status == "ATTACK":
            time_since_last = now - last_attack_time
            if time_since_last > COOLDOWN_DURATION:
                current_status = "Normal"
                print("✅ [INFO] Attack subsided. System returning to Normal.")

    # Optimized File I/O: Update JSON only periodically or on significant state change
    if total_packets % 10 == 0 or attack_detected or (current_status == "Normal" and now - last_attack_time < COOLDOWN_DURATION + 1):
        update_state_file(current_status, total_packets, total_attacks)

# --- ENTRY POINT ---
print(f"🚀 [SYSTEM START] SecureNet AI IDS Initialized...")
print(f"ℹ️  [CONFIG] Flood Threshold: {HTTP_FLOOD_THRESHOLD} req/s")
print("📡 Listening on interface 'en0'...")
print("Press Ctrl+C to stop")

# Reset State on Startup
update_state_file("Normal", 0, 0)

# Start Packet Sniffer (Scapy)
sniff(
    iface="en0",   
    prn=packet_handler,
    store=False
)

