#!/usr/bin/env python3
"""
SecBuddy - Log Reader (Phase 4)
Author: Yash Sharma

Integrated version:
✔ Reads auth.log
✔ Detects failed SSH attempts
✔ Groups attempts per IP
✔ Feeds to analyzer & recommender
✔ Prints full security report
"""

import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime

from .analyzer import analyze_ip
from .recommender import format_recommendation_output


DEFAULT_AUTH_LOG = "/var/log/auth.log"

FAILED_SSH_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_failed_ssh(log_path=DEFAULT_AUTH_LOG):
    log_file = Path(log_path)

    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        return

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_SSH_PATTERN.search(line)
            if match:
                data = match.groupdict()
                yield {
                    "ip": data["ip"],
                    "user": data["user"],
                    "raw": line.strip()
                }


def build_failed_attempt_summary(log_path=DEFAULT_AUTH_LOG):
    attempts = defaultdict(int)
    last_user_for_ip = {}

    for event in parse_failed_ssh(log_path):
        ip = event["ip"]
        user = event["user"]
        attempts[ip] += 1
        last_user_for_ip[ip] = user

    return attempts, last_user_for_ip


def generate_report():
    attempts, last_user = build_failed_attempt_summary()

    if not attempts:
        print("[INFO] No failed SSH attempts detected.")
        return

    print("\n===== SecBuddy SSH Security Report =====\n")

    for ip, count in sorted(attempts.items(), key=lambda x: x[1], reverse=True):
        user = last_user.get(ip, "unknown")

        analysis = analyze_ip(ip, count, user)
        report = format_recommendation_output(analysis)

        print(report)
        print("\n----------------------------------------\n")


def main():
    generate_report()


if __name__ == "__main__":
    main()
