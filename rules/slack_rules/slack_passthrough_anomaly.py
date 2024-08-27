from panther_base_helpers import slack_alert_context

ELEVATED_ANOMALIES = {"excessive_malware_uploads", "session_fingerprint", "unexpected_admin_action"}


def rule(event):
    return event.get("action") == "anomaly"


def severity(event):
    # Return "MEDIUM" for some more serious anomalies
    reasons = event.deep_get("details", "reason", default=[])
    if set(reasons) & ELEVATED_ANOMALIES:
        return "MEDIUM"
    return "DEFAULT"


def alert_context(event):
    context = slack_alert_context(event)
    context |= {"details": event.get("details", {}), "context": event.get("context", {})}
    return context
