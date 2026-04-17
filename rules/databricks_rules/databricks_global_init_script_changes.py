from panther_databricks_helpers import databricks_alert_context


def rule(event):
    return event.get("serviceName") == "globalInitScripts"


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    script_name = event.deep_get("requestParams", "name", default="Unknown Script")
    return f"Global init script {action}: {script_name} by {actor}"


def dedup(event):
    script_name = event.deep_get("requestParams", "name", default="unknown")
    script_id = event.deep_get("requestParams", "script_id", default="unknown")
    return f"global_init_script_{script_id}_{script_name}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "script_name": event.deep_get("requestParams", "name"),
            "script_id": event.deep_get("requestParams", "script_id"),
            "script_enabled": event.deep_get("requestParams", "enabled"),
            "script_sha256": event.deep_get("requestParams", "script-SHA256"),
        },
    )
