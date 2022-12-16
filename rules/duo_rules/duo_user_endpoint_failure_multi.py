from panther_base_helpers import deep_get


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
    user = deep_get(event, "user", "name", default="Unknown")
    reason = event.get("reason", "Unknown")
    return f"Duo User [{user}] encountered suspicious endpoint issue [{reason}]"


def alert_context(event):
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": deep_get(event, "user", "name", default=""),
        "os": deep_get(event, "access_device", "os", default=""),
        "ip_access": deep_get(event, "access_device", "ip", default=""),
        "ip_auth": deep_get(event, "auth_device", "ip", default=""),
        "application": deep_get(event, "application", "name", default=""),
    }
