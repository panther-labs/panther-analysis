from panther_databricks_helpers import databricks_alert_context, is_login_action


def rule(event):
    if not is_login_action(event):
        return False

    # Check for failure status codes
    status_code = event.deep_get("response", "statusCode")
    return status_code in [401, 403]


def title(event):
    user = event.deep_get("userIdentity", "email") or event.deep_get(
        "requestParams", "user", default="Unknown User"
    )
    source_ip = event.get("sourceIPAddress", "Unknown IP")
    action = event.get("actionName", "login")
    return f"Repeated failed login attempts: {user} from {source_ip} ({action})"


def dedup(event):
    user = (
        event.deep_get("userIdentity", "email")
        or event.deep_get("requestParams", "user")
        or "unknown"
    )
    return f"failed_login_{user}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "login_user": event.deep_get("userIdentity", "email")
            or event.deep_get("requestParams", "user"),
            "login_action": event.get("actionName"),
            "error_message": event.deep_get("response", "errorMessage"),
        },
    )
