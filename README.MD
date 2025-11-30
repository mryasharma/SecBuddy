# 🛡️ SecBuddy — Linux Security Log Intelligence Assistant

SecBuddy is a lightweight yet powerful **Linux security assistant** designed to analyze system logs, detect suspicious activity, and explain events in **simple human-readable language**.

Unlike traditional log analyzers, SecBuddy focuses on **clarity, real-time detection, and actionable security recommendations**.

---

## 🚀 Features

### 🔍 Log Monitoring
Monitors:
- `/var/log/auth.log`
- `/var/log/syslog`
- SSH activity
- Failed logins
- Sudo usage
- Unknown users attempting access

### 🧠 Intelligent Analysis
- Detects brute-force attacks  
- Suspicious login patterns  
- Abnormal sudo usage  
- User behavior deviation  

### 💬 Human-Readable Explanation
SecBuddy converts complex logs into simple explanations like:

```
[ALERT] 45.12.34.56 attempted 12 failed SSH logins in 3 minutes.
Explanation: This behavior resembles a brute-force attack.
Recommended Action: Block this IP immediately.
```

### ⚠️ Risk Scoring
Each event gets a **risk score (0–10)**.

### 🛠️ Recommendations Engine
Provides actionable suggestions:
- Block IP  
- Disable root login  
- Enforce SSH key authentication  
- Change SSH port  

### 📊 System Summary
Daily summary of:
- Successful logins  
- Failed logins  
- Suspicious IPs  
- High-risk events  

---

## 🧩 Project Goals

SecBuddy is built for:

- Linux learners  
- Security enthusiasts  
- System administrators  
- Anyone who wants a smart local security assistant  

---

## 📁 Folder Structure

```
SecBuddy/
├── secbuddy/
│   ├── log_reader.py
│   ├── analyzer.py
│   ├── recommender.py
│   ├── monitor.py
│   ├── cli.py
│
├── docs/
│   └── architecture.md
│
├── examples/
│   └── sample_output.png
│
├── tests/
│   └── test_basic.py
│
├── LICENSE
├── README.md
├── LICENSE
└── requirements.txt
```

---

## 🧪 Installation

```
git clone https://github.com/mryasharma/SecBuddy.git
cd SecBuddy
pip install -r requirements.txt
```

---

## ▶️ Usage

Start the CLI assistant:

```
python -m secbuddy.cli
```

Example commands:
```
scan-auth
scan-sudo
show-summary
explain-last 20
monitor-live
```

---

## 📜 License

Licensed under the **Apache License 2.0**.  
This project retains the copyright:

**(c) 2025 Yash Sharma**

---

## 👨‍💻 Author

**Yash Sharma**  
Creator & Maintainer of SecBuddy  
