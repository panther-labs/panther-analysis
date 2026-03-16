from panther_slack_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_unenrolled` action
    return event.get("action") == "ekm_unenrolled"


def title(event):
    actor = event.deep_get("actor", "user", "email", default="<UNKNOWN_ACTOR>")
    workspace = event.deep_get("context", "location", "domain", default="<UNKNOWN_WORKSPACE>")
    return (
        f"Slack: Workspace [{workspace}] unenrolled from Enterprise Key Management "
        f"by [{actor}] - Customer-controlled encryption disabled"
    )


def alert_context(event):
    return slack_alert_context(event)
