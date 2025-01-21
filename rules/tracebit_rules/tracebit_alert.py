def rule(event):
    return event.deep_get("discriminator", "type") == "tracebit_alert_log"


def title(event):
    return f"Tracebit: {event.get('message')}"


def dedup(event):
    # Deduplicate alerts based on the alert_id because there can be multiple alert logs for a single alert
    return event.get("alert_id")


def reference(event):
    # Reference the alert in the Tracebit portal to allow for easy investigation
    return event.get("tracebit_portal_url")


def severity(event):
    # Override the default alert severity if the alert log has a high severity
    if event.get("severity") == "High":
        return "HIGH"
    return "DEFAULT"
