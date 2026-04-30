from panther_msft_helpers import msft_graph_alert_context

SEVERITY_MAP = {
    "informational": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}


def rule(event):
    return event.get("status") == "new" and event.get("severity", "").lower() != "informational"


def title(event):
    return f"Microsoft Graph Alert ({event.get('title')})"


def dedup(event):
    return event.get("id")


def severity(event):
    return SEVERITY_MAP.get(event.get("severity", "").lower(), "INFO")


def alert_context(event):
    return msft_graph_alert_context(event)
