"""
SecBuddy - Analyzer (Phase 2)
Author: Yash Sharma

Takes raw failed-login data and produces:
✔ Risk Score (0–10)
✔ Explanation text
✔ Labels suspicious IPs
"""

def calculate_risk(attempt_count: int, attempted_user: str):
    """
    Calculate a numeric risk score based on attempts + username characteristics.
    """
    score = 0

    # Rule 1 — Many failed attempts = high risk
    if attempt_count >= 20:
        score += 10
    elif attempt_count >= 10:
        score += 8
    elif attempt_count >= 5:
        score += 5
    elif attempt_count >= 3:
        score += 3

    # Rule 2 — Attacking "root" user = extra risk
    if attempted_user.lower() == "root":
        score += 2

    # Rule 3 — Invalid/unknown users = suspicious
    if attempted_user.lower() in ["admin", "test", "user", "guest"]:
        score += 1

    # Score cap (max 10)
    return min(score, 10)


def explain(event):
    """
    Takes a single login event and returns a human-readable explanation.
    """
    attempts = event.get("attempts", 0)
    ip = event.get("ip")
    user = event.get("user")

    explanation = ""

    if attempts >= 10:
        explanation += (
            f"IP {ip} attempted {attempts} failed logins — "
            "this strongly resembles a brute-force attack. "
        )
    elif attempts >= 5:
        explanation += (
            f"IP {ip} is failing login attempts frequently. "
            "Possible password guessing."
        )
    elif attempts >= 3:
        explanation += (
            f"IP {ip} is showing unusual login failures. "
        )
    else:
        explanation += (
            f"IP {ip} has a few failed attempts. Monitoring suggested. "
        )

    # User-specific notes
    if user.lower() == "root":
        explanation += " Targeting the 'root' account is very dangerous."

    return explanation


def analyze_ip(ip, attempts, user):
    """
    Returns a full analysis object for a given IP.
    """
    score = calculate_risk(attempts, user)
    explanation = explain({"attempts": attempts, "ip": ip, "user": user})

    return {
        "ip": ip,
        "attempts": attempts,
        "user": user,
        "risk_score": score,
        "message": explanation
    }
