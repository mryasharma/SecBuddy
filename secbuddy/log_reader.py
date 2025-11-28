#!/usr/bin/env python3
"""
SecBuddy - Log Reader (Phase 1)
Author: Yash Sharma

Reads Linux auth.log and finds failed SSH login attempts.
"""

import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime


# Default path for auth log in most Linux systems
DEFAULT_AUTH_LOG = "/var/log/auth.log"


# Regex pattern to capture failed SSH attempts
FAILED_SSH_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_failed_ssh_lines(log_path: str = DEFAULT_AUTH_LOG):
    """
    Generator that yields info about each failed SSH login attempt.
    """
    log_file = Path(log_path)

    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        print("Make sure you're running this on a Linux system with /var/log/auth.log")
        return

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_SSH_PATTERN.search(line)
            if match:
                data = match.groupdict()
                yield {
                    "timestamp": _build_timestamp(data["month"], data["day"], data["time"]),
                    "host": data["host"],
                    "user": data["user"],
                    "ip": data["ip"],
                    "raw": line.strip(),
                }


def _build_timestamp(month: str, day: str, time_str: str) -> str:
    """
    Build a readable timestamp string from log parts.
    Year is assumed as current year.
    """
    current_year = datetime.now().year
    ts_str = f"{month} {day} {current_year} {time_str}"
    try:
        dt = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
        return dt.isoformat(sep=" ")
    except ValueError:
        return ts_str  # Fallback


def summarize_failed_attempts(log_path: str = DEFAULT_AUTH_LOG, min_threshold: int = 3):
    """
    Summarize failed SSH attempts per IP and print suspicious IPs
    (those with attempts >= min_threshold).
    """
    attempts_per_ip = defaultdict(int)

    print(f"[INFO] Reading failed SSH logins from: {log_path}")

    for event in parse_failed_ssh_lines(log_path):
        attempts_per_ip[event["ip"]] += 1

    if not attempts_per_ip:
        print("[INFO] No failed SSH login attempts found.")
        return

    print("\n=== Failed SSH Attempts Per IP ===")
    for ip, count in sorted(attempts_per_ip.items(), key=lambda x: x[1], reverse=True):
        status = "SUSPICIOUS" if count >= min_threshold else "OK"
        print(f"{ip:15} -> {count:3d} attempts   [{status}]")

    print("\n[INFO] Marking IPs with attempts >= "
          f"{min_threshold} as suspicious.")


def main():
    # For Phase 1, just run the summary
    summarize_failed_attempts()


if __name__ == "__main__":
    main()
