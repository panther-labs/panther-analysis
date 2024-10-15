from panther_base_helpers import slack_alert_context

DENIAL_OF_SERVICE_ACTIONS = [
    "bulk_session_reset_by_admin",
    "user_session_invalidated",
    "user_session_reset_by_admin",
]


def rule(event):
    # Only evaluate actions that could be used for a DoS
    if event.get("action") not in DENIAL_OF_SERVICE_ACTIONS:
        return False

    return True


def dedup(event):
    return f"Slack.AuditLogs.ApplicationDoS{event.deep_get('entity', 'user', 'name')}"


def alert_context(event):
    return slack_alert_context(event)
