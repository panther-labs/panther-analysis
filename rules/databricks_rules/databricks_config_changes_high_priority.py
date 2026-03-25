from panther_databricks_helpers import (
    databricks_alert_context,
    get_config_key_value,
    is_critical_config_change,
)


def rule(event):
    if not is_critical_config_change(event):
        return False

    # Verbose audit logging disabled is handled by a dedicated rule
    config_key, config_value = get_config_key_value(event)
    if config_key == "enableVerboseAuditLogs" and config_value == "false":
        return False

    return True


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    success = status_code == 200
    action = event.get("actionName")

    # Determine severity from action type
    #                        Success    Failure
    # IP access list deleted HIGH       MEDIUM
    # Other critical configs MEDIUM     LOW
    if action == "deleteIpAccessList":
        return "HIGH" if success else "MEDIUM"
    return "MEDIUM" if success else "LOW"


def title(event):
    action = event.get("actionName")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Successfully" if status_code == 200 else "Attempted to"

    # IP access list changes
    if "IpAccessList" in action:
        return f"{status} {action} by {actor}"

    # Workspace configuration edits
    config_key, config_value = get_config_key_value(event)
    if config_key:
        return f"{status} modify {config_key} to {config_value} by {actor}"

    return f"Critical configuration change by {actor}"


def dedup(event):
    config_key, _ = get_config_key_value(event)
    return f"critical_config_change_{config_key}"


def alert_context(event):
    config_key, config_value = get_config_key_value(event)
    return databricks_alert_context(
        event,
        additional_fields={
            "config_key": config_key,
            "config_value": config_value,
            "change_category": (
                "IP Access List"
                if "IpAccessList" in event.get("actionName", "")
                else "Workspace Configuration"
            ),
        },
    )
