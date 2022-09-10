from panther_base_helpers import github_alert_context

# {GitHub Action: Alert Severity}
ADV_SEC_ACTIONS = {
    "dependabot_alerts.disable": "CRITICAL",
    "dependabot_alerts_new_repos.disable": "HIGH",
    "dependabot_security_updates.disable": "CRITICAL",
    "dependabot_security_updates_new_repos.disable": "HIGH",
    "repository_secret_scanning_push_protection.disable": "HIGH",
    "secret_scanning.disable": "CRITICAL",
    "secret_scanning_new_repos.disable": "HIGH",
    "bypass": "MEDIUM",  # Bypass secret scanner push protection for a detected secret.
}


def rule(event):
    return event.get("action") in ADV_SEC_ACTIONS


def title(event):
    return f"Change detected to GitHub Advanced Security - {event.get('action')}"


def alert_context(event):
    return github_alert_context(event)


# Use the per action severity configured above
def severity(event):
    return ADV_SEC_ACTIONS.get(event.get("action", ""), "Low")
