# AI Real-Time Intrusion Detection System (IDS)

## 📌 Project Overview
This project implements a **Real-Time AI-based Intrusion Detection System (IDS)** that monitors live network traffic, detects abnormal behavior such as **HTTP flooding attacks**, and visualizes alerts on a **real-time dashboard**.

The system combines:
- **Machine Learning (Random Forest)**
- **Real-time packet capture**
- **Rate-based attack detection**
- **Live web dashboard**

It is designed as a **Final Year Project** and aligns with **AI / Cybersecurity engineering roles**.

---

## 🚀 Features
- Real-time packet sniffing using Scapy  
- AI-based traffic classification (Random Forest)  
- Hybrid detection (ML + traffic rate)  
- HTTP Flood (DoS) attack detection  
- Automatic return to normal state using inactivity timeout  
- Live dashboard using Streamlit  
- Cross-platform attack simulation (Windows → macOS)

---

## 🧠 System Architecture
1. Network packets are captured in real time
2. Features are extracted from packets
3. AI model classifies traffic
4. Rate-based logic detects flooding
5. Detection results are written to a shared state
6. Streamlit dashboard visualizes system status

---

## 🛠️ Technologies Used
- Python 3
- Scapy
- Scikit-learn
- Pandas / NumPy
- Streamlit
- Joblib
- Git & GitHub

---

## 📂 Project Structure

