from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "file_malicious_content_detected"


def title(event):
    uploader = event.deep_get("actor", "user", "email", default="<UNKNOWN_USER>")
    workspace = event.deep_get("context", "location", "domain", default="<UNKNOWN_WORKSPACE>")
    return (
        f"Slack: Malicious file detected in Slack workspace [{workspace}] "
        f"uploaded by [{uploader}] - Potential malware or phishing attack"
    )


def alert_context(event):
    return slack_alert_context(event)
