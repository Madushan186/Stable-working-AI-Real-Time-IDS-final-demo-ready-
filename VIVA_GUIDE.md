# 🎓 Final Year Project - Viva Guide
## Title: AI-Based Real-Time Intrusion Detection System
**Developed by:** Lakshitha Madushan

---

## 1. System Architecture
### Q: How does your system work in real-time?
**Answer:**
My system consists of three main decoupled components:
1.  **Packet Sniffer (`realtime_ids.py`)**: Uses `Scapy` to capture packets directly from the network interface (`en0`). It runs an infinite loop to process traffic.
2.  **Detection Engine**:
    *   **Rule-Based**: Checks for high-volume traffic (HTTP Flood) using a sliding window of timestamps (Rate Limiting).
    *   **ML-Based**: Extracts 41 characteristics (Protocol, Size, Flags) and passes them to a pre-trained **Random Forest** model.
3.  **Visualization (`dashboard.py`)**: A `Streamlit` app that reads the shared state (JSON) and logs (CSV) to display live updates without blocking the detection engine.

### Q: Why did you use Hybrid Detection?
**Answer:**
*   **Machine Learning** is great for complex, unknown patterns but can be slow or heavy.
*   **Rule-Based systems** are instant and low-cost but rigid.
*   By combining them, I get **Speed** (Rules detecting floods instantly) and **Intelligence** (ML detecting subtle anomalies).

---

## 2. Technical Decisions
### Q: How do you handle Concurrency/Performance?
**Answer:**
I use **Atomic File Operations** for state management.
*   The backend writes to `ids_state.json.tmp` and then renames it to `ids_state.json`.
*   This ensures the dashboard never reads a half-written file, preventing "JSON Decode Errors" during high-speed attacks.
*   I also use `collections.deque` for the sliding window because appending/popping is O(1) complexity, making it much faster than a standard list.

### Q: Why Random Forest?
**Answer:**
I chose Random Forest because:
1.  It handles high-dimensional data (41 features) very well.
2.  It is less prone to overfitting than Decision Trees.
3.  It provides feature importance, making it explainable (White-box AI).
4.  It is faster to train and infer compared to Deep Neural Networks (DNN) for tabular network data.

---

## 3. Notable Challenges & Solutions
1.  **Dashboard Flickering**: When an attack stops, the status shouldn't change instantly. I implemented a **3-second Cooldown Mechanism** in the backend to stabilize the UI.
2.  **Interface Permissions**: Scapy requires root access. I handled this by documenting `sudo` usage and adding permission checks in my scripts.

---

## 4. Key Metrics
*   **Detection Latency**: < 50ms per packet.
*   **Throughput**: Can process ~200 packets/sec (software limit).
*   **Accuracy**: ~99.8% on the CICIDS2017 test set.
