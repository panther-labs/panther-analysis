from panther_base_helpers import github_alert_context

#pylint: disable=line-too-long

# {GitHub Action: Alert Severity}
ADV_SEC_ACTIONS = {
    "dependabot_alerts.disable": "CRITICAL",                        # An enterprise owner or site administrator disabled Dependabot alerts for all existing repositories.
    "dependabot_alerts_new_repos.disable": "HIGH",                  # An enterprise owner or site administrator disabled Dependabot alerts for all new repositories.
    "dependabot_security_updates.disable": "CRITICAL",              # An enterprise owner or site administrator disabled Dependabot security updates for all existing repositories.
    "dependabot_security_updates_new_repos.disable": "HIGH",        # An enterprise owner or site administrator disabled Dependabot security updates for all new repositories.
    "repository_secret_scanning_push_protection.disable": "HIGH",   # A repository owner or administrator disabled secret scanning for a repository.
    "secret_scanning.disable": "CRITICAL",                          # An organization owner disabled secret scanning for all existing repositories.
    "secret_scanning_new_repos.disable": "HIGH",                    # An organization owner disabled secret scanning for all new repositories.
}


def rule(event):
    return event.get("action") in ADV_SEC_ACTIONS


def title(event):
    return f"Change detected to GitHub Advanced Security - {event.get('action')}"

def alert_context(event):
    return github_alert_context(event)

# Use the per action severity configured above
def severity(event):
    return ADV_SEC_ACTIONS.get(event.get("action"))
