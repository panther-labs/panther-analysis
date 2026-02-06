from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "intune_disabled"


def title(event):
    actor = event.deep_get("actor", "user", "email", default="<UNKNOWN_ACTOR>")
    workspace = event.deep_get("context", "location", "domain", default="<UNKNOWN_WORKSPACE>")
    return (
        f"CRITICAL: Microsoft Intune MDM disabled for Slack workspace [{workspace}] "
        f"by [{actor}] - Mobile security controls removed"
    )


def alert_context(event):
    return slack_alert_context(event)
