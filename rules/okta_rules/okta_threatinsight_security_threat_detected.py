from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") == "security.threat.detected"


def title(event):
    return f"Okta Security [{event.get('severity', '')}] Threat Detected "


def alert_context(event):
    return okta_alert_context(event)
