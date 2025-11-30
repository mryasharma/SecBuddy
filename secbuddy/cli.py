"""
SecBuddy - CLI Interface
Author: Yash Sharma

Command-line entrypoint for SecBuddy.

Usage examples (Linux):
    python3 -m secbuddy.cli scan-auth
    python3 -m secbuddy.cli summary
    python3 -m secbuddy.cli export
    python3 -m secbuddy.cli export --json
    python3 -m secbuddy.cli export --csv
    python3 -m secbuddy.cli email-report --smtp smtp.gmail.com --user you@gmail.com --to you@gmail.com
"""

import argparse

from .log_reader import generate_report, build_failed_attempt_summary
from .exporter import export_to_json, export_to_csv
from .email_notifier import send_email_report


def cmd_scan_auth(args):
    """
    Run full SSH security report.
    """
    print("[SecBuddy] Scanning auth.log for failed SSH attempts...\n")
    generate_report()


def cmd_summary(args):
    """
    Show only a brief summary of failed attempts per IP.
    """
    attempts, _last_user = build_failed_attempt_summary()

    if not attempts:
        print("[SecBuddy] No failed SSH attempts found.")
        return

    print("===== SecBuddy SSH Summary =====\n")
    total = 0
    for ip, count in sorted(attempts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:15} -> {count:3d} failed attempts")
        total += count

    print(f"\nTotal failed attempts: {total}")
    print(f"Unique attacking IPs: {len(attempts)}")


def cmd_export(args):
    """
    Export report to files.
    Default: if no flag given, export both JSON and CSV.
    """
    do_json = args.json or (not args.json and not args.csv)
    do_csv = args.csv or (not args.json and not args.csv)

    if do_json:
        export_to_json()

    if do_csv:
        export_to_csv()


def cmd_email_report(args):
    """
    Send email report using SMTP credentials.
    NOTE: For Gmail, use an App Password (not your normal login password).
    """
    import getpass

    password = getpass.getpass("Enter SMTP password (or app password): ")

    send_email_report(
        smtp_server=args.smtp,
        smtp_port=args.port,
        username=args.user,
        password=password,
        to_email=args.to,
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secbuddy",
        description="SecBuddy - Linux Security Log Intelligence Assistant",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        required=True,
        help="Available SecBuddy commands",
    )

    # Command: scan-auth
    scan_parser = subparsers.add_parser(
        "scan-auth",
        help="Run full analysis on auth.log and show detailed report",
    )
    scan_parser.set_defaults(func=cmd_scan_auth)

    # Command: summary
    summary_parser = subparsers.add_parser(
        "summary",
        help="Show only a short summary of failed SSH attempts per IP",
    )
    summary_parser.set_defaults(func=cmd_summary)

    # Command: export
    export_parser = subparsers.add_parser(
        "export",
        help="Export analysis report to JSON and/or CSV",
    )
    export_parser.add_argument(
        "--json",
        action="store_true",
        help="Export report as JSON",
    )
    export_parser.add_argument(
        "--csv",
        action="store_true",
        help="Export report as CSV",
    )
    export_parser.set_defaults(func=cmd_export)

    # Command: email-report
    email_parser = subparsers.add_parser(
        "email-report",
        help="Send a summary report via email",
    )
    email_parser.add_argument(
        "--smtp",
        required=True,
        help="SMTP server (e.g. smtp.gmail.com)",
    )
    email_parser.add_argument(
        "--port",
        type=int,
        default=587,
        help="SMTP port (default: 587)",
    )
    email_parser.add_argument(
        "--user",
        required=True,
        help="SMTP username / from email address",
    )
    email_parser.add_argument(
        "--to",
        required=True,
        help="Recipient email address",
    )
    email_parser.set_defaults(func=cmd_email_report)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
