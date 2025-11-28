"""
SecBuddy - CLI Interface (Phase 5)
Author: Yash Sharma

Command-line entrypoint for SecBuddy.

Usage examples:
    python -m secbuddy.cli scan-auth
    python -m secbuddy.cli summary
"""

import argparse

from .log_reader import generate_report, build_failed_attempt_summary


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

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
