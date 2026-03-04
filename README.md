# 🔐 SentinelShield – Advanced Intrusion Detection & Web Protection System

Lightweight Web Application Firewall (WAF) & Intrusion Detection System (IDS) simulation developed during my Cybersecurity Internship at Unified Mentor.

---

## 📘 Project Overview

SentinelShield is a lightweight WAF & IDS simulation that inspects HTTP requests, detects malicious patterns using a rule engine, enforces IP-based rate limiting, logs security events, and generates statistical dashboards for analysis.

This project demonstrates real-world SOC monitoring workflow:

Detection → Decision → Logging → Alerting → Dashboarding

---

## 🚀 Key Features

- SQL Injection Detection  
- Cross-Site Scripting (XSS) Detection  
- Local File Inclusion (LFI) Detection  
- Command Injection Detection  
- Directory Traversal Detection  
- IP-based Rate Limiting  
- JSON Structured Logging  
- CSV Export for Analysis  
- Detection Accuracy Calculation  
- Statistical Visualization (Charts)

---

## 🏗 System Architecture
User Request
↓
SentinelShield Proxy (Port 5000)
↓
Rule Engine & Rate Limiter
↓
Decision (Allow / Block)
↓
Logging Module
↓
Dashboard & Analytics
↓
Victim Application (Port 5001)

---

## 🛠 Tech Stack

- Python  
- Flask  
- Pandas  
- Matplotlib  
- Kali Linux  

---

## 🚀 How To Run

### 1️⃣ Start Victim Application

python victim_app.py

2️⃣ Start SentinelShield Proxy

python sentinelshield.py

3️⃣ Run Attack Simulation

python attack_simulator.py

4️⃣ Open Dashboard

http://127.0.0.1:5000/dashboard

📊 Detection Accuracy

Detection Accuracy Formula:

(Correctly Blocked Malicious Requests / Total Malicious Attempts) × 100
📁 Internship Details

Organization: Unified Mentor

Role: Cybersecurity Intern

Project: SentinelShield – Advanced Intrusion Detection & Web Protection System

🔮 Future Improvements

Machine Learning-based anomaly detection

SIEM integration

Geo-IP tracking

Real-time alerting

🏆 Learning Outcomes

HTTP request inspection

Signature-based detection

Behavioral traffic analysis

Security logging and reporting

Dashboard analytics

## 📄 Detailed Project Report

https://docs.google.com/document/d/1UOEQrtXQbhsvE7QEzG7m3MkgEkmoJwpOaVkRyMTUdaA/edit?usp=sharing

