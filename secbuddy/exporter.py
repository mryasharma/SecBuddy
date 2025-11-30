"""
SecBuddy - Exporter (Log Export Feature)
Author: Yash Sharma

Exports analyzed SSH attack data to JSON / CSV files.
"""

import json
import csv
from pathlib import Path

from .log_reader import get_ip_analysis


EXPORT_DIR = Path("exports")
EXPORT_DIR.mkdir(exist_ok=True)


def export_to_json(filepath: str = "exports/secbuddy_report.json"):
    analyses = get_ip_analysis()
    path = Path(filepath)

    with path.open("w", encoding="utf-8") as f:
        json.dump(analyses, f, indent=4)

    print(f"[SecBuddy] JSON report exported to: {path.resolve()}")


def export_to_csv(filepath: str = "exports/secbuddy_report.csv"):
    analyses = get_ip_analysis()
    path = Path(filepath)

    if not analyses:
        print("[SecBuddy] No data to export.")
        return

    fieldnames = ["ip", "user", "attempts", "risk_score", "message"]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(analyses)

    print(f"[SecBuddy] CSV report exported to: {path.resolve()}")
        
