# AI Real-Time Intrusion Detection System (IDS)

## 📌 Project Overview
This project implements a **Real-Time AI-based Intrusion Detection System (IDS)** that monitors live network traffic, detects abnormal behavior using a **Hybrid AI Architecture** (Random Forest + Isolation Forest), and visualizes alerts on a **real-time dashboard**.

It is designed as a **Final Year Project** and aligns with **AI / Cybersecurity engineering roles**.

---

## 🚀 Quick Start Guide

### 1️⃣ How to Start
The easiest way to run the entire system (Detection Engine + Dashboard) is using the helper script:

```bash
sudo ./run_ids.sh
```

**Manual Start (Alternative):**
If you prefer to run components separately in two terminals:

**Terminal 1 (Detection Engine):**
```bash
sudo python3 realtime_ids.py
```

**Terminal 2 (Dashboard):**
```bash
streamlit run dashboard.py
```

---

### 2️⃣ How to Stop
To safely stop the system:

1.  **Press `Ctrl + C`** in the terminal where the script is running.
2.  If you ran the components separately, go to **both** terminals and press `Ctrl + C`.

The system handles shutdown gracefully:
- Logs are saved.
- Network sniffers are released.
- File handles are closed.

---

## 🧪 Simulation
To test the detection capabilities, run the attack simulator in a separate terminal:

```bash
sudo python3 simulate_attack.py
```
This sends harmless packets that mimic an HTTP Flood attack to trigger the system.

---

## 🧠 System Architecture (Hybrid AI)
1.  **Victim Server**: Python HTTP Server running on `Port 8080`.
2.  **Traffic Analysis (Rules)**: Detects high-volume DoS attacks (>20 req/s).
3.  **Random Forest (Supervised AI)**: Detects known attack patterns (SQLi, Brute Force).
4.  **Isolation Forest (Unsupervised AI)**: Detects zero-day anomalies.
5.  **Dashboard**: Visualizes Confidence, Severity, and Detection Source.

---

## 🛠️ Technologies Used
- **Python 3**
- **Scapy** (Packet Capture)
- **Scikit-learn** (AI Models)
- **Streamlit** (Dashboard)
- **Pandas / NumPy** (Data Processing)

---

## 📂 Project Structure
- `realtime_ids.py`: Main detection engine.
- `dashboard.py`: Visualization interface.
- `simulate_attack.py`: Attack testing tool.
- `training/train_model.py`: Script to retrain AI models.
- `models/`: Stores `rf_ids_model.pkl` and `iso_forest.pkl`.
- `data/`: Contains KDDTrain+ dataset.
