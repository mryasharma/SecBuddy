"""
SecBuddy - Recommender (Phase 3)
Author: Yash Sharma

Takes analyzed security events and suggests actions.
"""

def recommend_actions(analysis: dict):
    """
    Input: analysis dict from analyzer.analyze_ip(...)
    Output: list of recommended actions (strings)
    """
    ip = analysis.get("ip")
    attempts = analysis.get("attempts", 0)
    user = analysis.get("user", "").lower()
    score = analysis.get("risk_score", 0)

    actions = []

    # High-risk → immediate blocking
    if score >= 8 or attempts >= 15:
        actions.append(
            f"Immediately block IP {ip} using firewall (ufw/iptables)."
        )

    # Repeated failures → add SSH hardening
    if attempts >= 5:
        actions.append(
            "Enforce SSH key-based authentication instead of password logins."
        )

    # Root targeted → disable direct root login
    if user == "root":
        actions.append(
            "Disable direct root SSH login (set 'PermitRootLogin no' in sshd_config)."
        )

    # General security hardening suggestions
    if score >= 5:
        actions.append("Review SSH logs regularly for similar patterns.")
        actions.append("Consider changing the SSH port to a non-default one.")
    elif score >= 3:
        actions.append("Monitor this IP for future failed login attempts.")
    else:
        actions.append("No immediate action required. Keep monitoring.")

    # Always add a generic note
    actions.append("Ensure all user accounts use strong, unique passwords.")

    return actions


def format_recommendation_output(analysis: dict):
    """
    Create a nice multi-line string combining analysis + recommendations.
    """
    lines = []
    lines.append(f"IP:           {analysis.get('ip')}")
    lines.append(f"User:         {analysis.get('user')}")
    lines.append(f"Attempts:     {analysis.get('attempts')}")
    lines.append(f"Risk score:   {analysis.get('risk_score')}/10")
    lines.append("")
    lines.append("Explanation:")
    lines.append(f"  {analysis.get('message')}")
    lines.append("")
    lines.append("Recommended actions:")

    actions = recommend_actions(analysis)
    for idx, action in enumerate(actions, start=1):
        lines.append(f"  {idx}. {action}")

    return "\n".join(lines)
