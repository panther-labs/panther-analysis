from panther_base_helpers import slack_alert_context

DLP_ACTIONS = [
    "native_dlp_rule_deactivated",
    "native_dlp_violation_deleted",
]


def rule(event):
    return event.get("action") in DLP_ACTIONS


def title(event):
    if event.get("action") == "native_dlp_rule_deactivated":
        return "Slack DLP Rule Deactivated"
    return "Slack DLP Violation Deleted"


# DLP violations can be removed by security engineers in the case of FPs
# We still want to alert on these, however those should not constitute a High severity
def severity(event):
    if event.get("action") == "native_dlp_violation_deleted":
        return "Medium"
    return "High"


def alert_context(event):
    return slack_alert_context(event)
