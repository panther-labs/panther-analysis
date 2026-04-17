from panther_databricks_helpers import databricks_alert_context, is_metastore_admin_action


def rule(event):
    # Use helper to check for metastore admin actions
    if not is_metastore_admin_action(event):
        return False

    action = event.get("actionName", "")

    # For group membership changes, only alert on additions (not removals)
    # and ensure it's at the account level
    if action != "updateMetastore":
        # Exclude removals
        if action == "removePrincipalFromGroup":
            return False
        # Must be account-level event
        if event.get("serviceName") != "accounts":
            return False

    return True


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
