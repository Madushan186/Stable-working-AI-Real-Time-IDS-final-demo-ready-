import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, TCP, UDP, ICMP
from collections import deque
import time

last_packet_time = time.time()
INACTIVITY_TIMEOUT = 3  # seconds

last_attack_time = 0
ATTACK_COOLDOWN = 5  # seconds

packet_times = deque(maxlen=100)


# Load trained ML model
model = joblib.load("models/rf_ids_model.pkl")

start_time = time.time()
packet_counter = 0

# Feature column names (same as training)
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

def extract_features(packet):
    global packet_counter
    packet_counter += 1

    duration = time.time() - start_time

    # Protocol encoding
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

    # Create 41-length feature vector
    features = np.zeros(41)
    features[0] = duration
    features[1] = protocol
    features[4] = src_bytes
    features[5] = dst_bytes
    features[22] = packet_counter
    features[23] = packet_counter

    # Convert to DataFrame (FIXES WARNING)
    df = pd.DataFrame(features.reshape(1, -1), columns=columns)
    return df
def update_state(is_attack):
    state = {"total": 0, "attacks": 0, "status": "Normal"}

    try:
        with open("ids_state.json", "r") as f:
            state = json.load(f)
    except:
        pass  # file may be empty temporarily

    state["total"] += 1

    if is_attack:
        state["attacks"] += 1
        state["status"] = "ATTACK"
    else:
        state["status"] = "Normal"

    # atomic write
    with open("ids_state.json.tmp", "w") as f:
        json.dump(state, f)

    os.replace("ids_state.json.tmp", "ids_state.json")

def packet_handler(packet):
    global last_attack_time, last_packet_time

    # Only monitor HTTP traffic to port 8080
    if TCP not in packet or packet[TCP].dport != 8080:
        return

    now = time.time()
    last_packet_time = now
    packet_times.append(now)

    # Calculate rate
    if len(packet_times) >= 2:
        rate = len(packet_times) / (packet_times[-1] - packet_times[0] + 0.0001)
    else:
        rate = 0

    # Attack detection
    if rate > 5:
        last_attack_time = now
        print(f"🚨 ATTACK DETECTED (High Rate: {rate:.2f} pps)")
        update_state(True)
        return

    # If traffic exists but below threshold
    print("Normal traffic")
    update_state(False)

def inactivity_monitor():
    while True:
        time.sleep(1)
        if time.time() - last_packet_time > INACTIVITY_TIMEOUT:
            packet_times.clear()
            print("Normal traffic (inactivity)")
            update_state(False)


print("🚀 Real-Time IDS running... Press Ctrl+C to stop")

import threading
threading.Thread(target=inactivity_monitor, daemon=True).start()

sniff(
    iface="en0",   # change if your interface is different
    prn=packet_handler,
    store=False
)

