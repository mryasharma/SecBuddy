# 🛡️ SecBuddy — Linux Security Log Intelligence Assistant

SecBuddy is a lightweight yet powerful **Linux security assistant** that analyzes SSH authentication logs, detects suspicious login activity, scores the risk, and suggests clear, actionable security steps.

It is built to help:
- Linux learners
- Cyber security students
- System administrators
- Anyone who wants to understand what's happening in `/var/log/auth.log`

---

## 🚀 Key Features

### 🔍 SSH Failed Login Detection
- Parses `/var/log/auth.log`
- Detects failed SSH login attempts
- Groups attempts by source IP
- Tracks which user was targeted (`root`, normal users, invalid users, etc.)

### 🧠 Risk-Based Analysis
For each attacking IP, SecBuddy:
- Counts total failed attempts
- Checks if `root` account was targeted
- Computes a **risk score (0–10)**
- Detects brute-force–like patterns

Example:

```text
IP:           45.67.89.10
User:         root
Attempts:     51
Risk score:   10/10

Explanation:
  IP 45.67.89.10 attempted 51 failed logins – this strongly resembles a brute-force attack.
  Targeting the 'root' account is very dangerous.

Recommended actions:
  1. Immediately block IP using firewall (ufw/iptables).
  2. Enforce SSH key-based authentication instead of password logins.
  3. Disable direct root SSH login (set 'PermitRootLogin no' in sshd_config).
  4. Review SSH logs regularly for similar patterns.
  5. Consider changing the SSH port to a non-default one.
  6. Ensure all user accounts use strong, unique passwords.
💬 Human-Readable Explanations
SecBuddy doesn’t just show log lines —
it explains what’s happening in simple language and marks IPs as:

Normal / Monitoring

Unusual

Suspicious

High-Risk (Brute-force)

📊 JSON / CSV Export
You can export a full analysis report for all attacking IPs:

bash
Copy code
python3 -m secbuddy.cli export          # export JSON + CSV
python3 -m secbuddy.cli export --json   # JSON only
python3 -m secbuddy.cli export --csv    # CSV only
This creates:

text
Copy code
exports/secbuddy_report.json
exports/secbuddy_report.csv
which can be used for:

Reporting

Forensics

Assignments / project documentation

Feeding into other tools

📧 (Optional) Email Report
SecBuddy can also send a summary report via email using SMTP:

bash
Copy code
python3 -m secbuddy.cli email-report \
  --smtp smtp.gmail.com \
  --user "your-email@example.com" \
  --to "recipient@example.com"
Note: For Gmail, you should use an app password, not your main login password.

🧩 Project Structure
text
Copy code
SecBuddy/
├── secbuddy/
│   ├── __init__.py
│   ├── log_reader.py        # Reads auth.log and builds attack summary
│   ├── analyzer.py          # Risk scoring + explanations
│   ├── recommender.py       # Security action suggestions
│   ├── cli.py               # Command-line interface
│   ├── exporter.py          # JSON / CSV export
│   └── email_notifier.py    # Email summary (optional)
├── exports/                 # Generated reports (ignored by Git, usually)
├── README.md
├── LICENSE
└── requirements.txt
⚙️ Installation (Linux / WSL Ubuntu)
bash
Copy code
# Go to your project folder
cd /mnt/c/Users/Yash/Desktop/SecBuddy   # or your path

# (Optional) Install pip if not installed
sudo apt update
sudo apt install -y python3-pip

# Install Python dependencies
pip install -r requirements.txt
▶️ Usage
1️⃣ Summary of failed SSH attempts
bash
Copy code
python3 -m secbuddy.cli summary
Shows:

Each attacking IP

Number of failed attempts

Totals

2️⃣ Full detailed report (with risk & actions)
bash
Copy code
python3 -m secbuddy.cli scan-auth
Shows, for each IP:

Attempts

Targeted user

Risk score

Explanation

Recommended actions (firewall, SSH config, monitoring, etc.)

3️⃣ Export reports
bash
Copy code
python3 -m secbuddy.cli export          # JSON + CSV
python3 -m secbuddy.cli export --json   # JSON only
python3 -m secbuddy.cli export --csv    # CSV only
🧪 Simulating Attacks (for Demo / Testing)
To simulate a brute-force attack in a test environment (WSL / lab machine):

bash
Copy code
sudo bash -c 'for i in {1..50}; do echo "Jan 20 12:45:00 yash sshd[1234]: Failed password for invalid user root from 45.67.89.10 port 5432 ssh2" >> /var/log/auth.log; done'

python3 -m secbuddy.cli scan-auth
You will see a high-risk report for IP 45.67.89.10.

⚠ Use this only on your own lab machine / WSL. Never tamper with production logs.

📝 License
This project is licensed under the Apache License 2.0.
See the LICENSE file for details.

Copyright (c) 2025 Yash Sharma

👨‍💻 Author
Yash Sharma
Creator & Maintainer — SecBuddy
GitHub: @mryasharma
