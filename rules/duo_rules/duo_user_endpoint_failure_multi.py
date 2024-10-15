def rule(event):
    endpoint_reasons = [
        "endpoint_is_not_in_management_system",
        "endpoint_failed_google_verification",
        "endpoint_is_not_trusted",
        "could_not_determine_if_endpoint_was_trusted",
        "invalid_device",
    ]
    return event.get("reason", "") in endpoint_reasons


def title(event):
    user = event.deep_get("user", "name", default="Unknown")
    reason = event.get("reason", "Unknown")
    return f"Duo User [{user}] encountered suspicious endpoint issue [{reason}]"


def alert_context(event):
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": event.deep_get("user", "name", default=""),
        "os": event.deep_get("access_device", "os", default=""),
        "ip_access": event.deep_get("access_device", "ip", default=""),
        "ip_auth": event.deep_get("auth_device", "ip", default=""),
        "application": event.deep_get("application", "name", default=""),
    }
