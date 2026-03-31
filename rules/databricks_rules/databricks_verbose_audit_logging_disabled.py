from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "workspace":
        return False

    if event.get("actionName") != "workspaceConfEdit":
        return False

    # Check if the configuration key is for verbose audit logs
    conf_key = event.deep_get("requestParams", "workspaceConfKeys")
    if conf_key != "enableVerboseAuditLogs":
        return False

    # Check if verbose logging is being disabled
    conf_value = event.deep_get("requestParams", "workspaceConfValues")
    return conf_value == "false"


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    return "CRITICAL" if status_code == 200 else "HIGH"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Successfully disabled" if status_code == 200 else "Attempted to disable"
    return f"Verbose audit logging {status} by {actor}"


def alert_context(event):
    conf_value = event.deep_get("requestParams", "workspaceConfValues")
    return databricks_alert_context(
        event,
        additional_fields={
            "config_key": event.deep_get("requestParams", "workspaceConfKeys"),
            "config_value": conf_value,
            "config_status": "Disabled" if conf_value == "false" else "Enabled",
        },
    )
