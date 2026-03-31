from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "ssoConfigBackend":
        return False

    return event.get("actionName") in ["create", "update"]


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    return "MEDIUM" if status_code == 200 else "LOW"


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    sso_status = event.deep_get("requestParams", "status", default="Unknown Status")
    return f"SSO configuration {action}d by {actor} - Status: {sso_status}"


def dedup(event):
    action = event.get("actionName", "unknown")
    return f"sso_config_{action}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "sso_status": event.deep_get("requestParams", "status"),
            "sso_config": event.deep_get("requestParams", "config"),
        },
    )
