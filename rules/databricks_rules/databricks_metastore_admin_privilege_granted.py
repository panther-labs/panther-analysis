from panther_databricks_helpers import (
    ADMIN_PRIVILEGE_ACTIONS,
    databricks_alert_context,
    extract_group_identifier,
    is_admin_group,
)


def rule(event):
    action = event.get("actionName")

    # Direct metastore ownership change
    if action == "updateMetastore":
        return "owner" in event.get("requestParams", {})

    # Admin group membership additions only (not removals)
    if action in ADMIN_PRIVILEGE_ACTIONS["group"] and action != "removePrincipalFromGroup":
        if event.get("serviceName") != "accounts":
            return False
        group = extract_group_identifier(event)
        if not group or not is_admin_group(group):
            return False
        metastore_keywords = ["metastore", "unity", "catalog"]
        return any(keyword in group.lower() for keyword in metastore_keywords)

    return False


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")

    if action == "updateMetastore":
        new_owner = event.deep_get("requestParams", "owner", default="Unknown Owner")
        return f"Metastore ownership changed to {new_owner} by {actor}"
    target_group = event.deep_get("requestParams", "targetGroupName", default="Unknown Group")
    principal = event.deep_get("requestParams", "principal") or event.deep_get(
        "requestParams", "targetUserName", default="Unknown Principal"
    )
    return f"Principal {principal} added to metastore admin group {target_group} by {actor}"


def dedup(event):
    action = event.get("actionName", "unknown")
    if action == "updateMetastore":
        metastore_id = event.deep_get("requestParams", "metastoreId", default="unknown")
        return f"metastore_admin_{metastore_id}"
    principal = event.deep_get("requestParams", "principal") or event.deep_get(
        "requestParams", "targetUserName", default="unknown"
    )
    return f"metastore_admin_group_{principal}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "new_owner": event.deep_get("requestParams", "owner"),
            "target_group": event.deep_get("requestParams", "targetGroupName"),
            "principal": event.deep_get("requestParams", "principal")
            or event.deep_get("requestParams", "targetUserName"),
        },
    )
