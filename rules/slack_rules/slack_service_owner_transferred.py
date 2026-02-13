from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "service_owner_transferred"


def title(event):
    previous_owner = event.deep_get("actor", "user", "email", default="<UNKNOWN_PREVIOUS_OWNER>")
    new_owner = event.deep_get("entity", "user", "email", default="<UNKNOWN_NEW_OWNER>")
    workspace = event.deep_get("context", "location", "domain", default="<UNKNOWN_WORKSPACE>")
    return (
        f"Slack: Primary Owner transferred for workspace [{workspace}] "
        f"from [{previous_owner}] to [{new_owner}] - Highest privilege transfer"
    )


def alert_context(event):
    return slack_alert_context(event)
