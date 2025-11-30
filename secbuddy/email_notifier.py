"""
SecBuddy - Email Notifier
Author: Yash Sharma

Sends a simple SSH security summary via email.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .log_reader import get_ip_analysis


def build_plaintext_summary():
    analyses = get_ip_analysis()

    if not analyses:
        return "[SecBuddy] No failed SSH attempts detected."

    lines = []
    total_attempts = sum(a["attempts"] for a in analyses)
    lines.append("SecBuddy SSH Security Summary\n")
    lines.append(f"Total attacking IPs: {len(analyses)}")
    lines.append(f"Total failed attempts: {total_attempts}")
    lines.append("")

    for a in analyses:
        lines.append(
            f"IP {a['ip']} | user: {a['user']} | attempts: {a['attempts']} | risk: {a['risk_score']}/10"
        )

    return "\n".join(lines)


def send_email_report(
    smtp_server: str,
    smtp_port: int,
    username: str,
    password: str,
    to_email: str,
):
    """
    Basic email sender.
    Uses SMTP.
    """

    body = build_plaintext_summary()

    msg = MIMEMultipart()
    msg["From"] = username
    msg["To"] = to_email
    msg["Subject"] = "SecBuddy SSH Security Report"

    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)

        print(f"[SecBuddy] Email report sent to {to_email}")
    except Exception as e:
        print(f"[SecBuddy] Failed to send email: {e}")
