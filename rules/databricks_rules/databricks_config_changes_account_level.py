from panther_databricks_helpers import databricks_alert_context, is_config_change


def rule(event):
    # Must be account-level audit event
    if event.get("auditLevel") != "ACCOUNT_LEVEL":
        return False

    # Account settings changes
    if is_config_change(event, config_category="account"):
        return True

    # SSO configuration changes
    if is_config_change(event, config_category="sso"):
        return True

    return False


def title(event):
    action = event.get("actionName", "Unknown Action")
    service = event.get("serviceName", "Unknown Service")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Success" if status_code == 200 else "Failed"

    return f"Account-level configuration change ({service}.{action}) by {actor} - {status}"


def dedup(event):
    service = event.get("serviceName", "unknown")
    action = event.get("actionName", "unknown")
    return f"account_config_change_{service}_{action}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "change_scope": "ACCOUNT_LEVEL",
            "request_params": event.get("requestParams"),
        },
    )
