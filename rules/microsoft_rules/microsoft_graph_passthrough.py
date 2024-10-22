from panther_msft_helpers import msft_graph_alert_context


def rule(event):
    return (
        event.get("status") == "newAlert" and event.get("severity", "").lower() != "informational"
    )


def title(event):
    return f"Microsoft Graph Alert ({event.get('title')})"


def dedup(event):
    return event.get("id")


def severity(event):
    if event.get("severity", "").lower() == "informational":
        return "INFO"
    return event.get("severity")


def alert_context(event):
    return msft_graph_alert_context(event)
