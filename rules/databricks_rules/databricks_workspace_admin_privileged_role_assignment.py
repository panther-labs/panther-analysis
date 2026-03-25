from panther_databricks_helpers import (
    databricks_alert_context,
    extract_group_identifier,
    extract_target_principal,
    get_principal_type,
    is_admin_privilege_action,
)


def rule(event):
    # Only match workspace-level events to avoid overlap with the
    # account-level admin privilege rule
    if event.get("auditLevel") != "WORKSPACE_LEVEL":
        return False

    # Use helper to check for admin privilege actions
    return is_admin_privilege_action(event)


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    return "HIGH" if status_code == 200 else "MEDIUM"


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    target = extract_target_principal(event) or "Unknown Principal"
    workspace = event.get("workspaceId", "Unknown Workspace")
    status_code = event.deep_get("response", "statusCode")
    status = "Granted" if status_code == 200 else "Attempted to grant"

    # Check if it's direct admin action or group-based
    if action in ["setAdmin", "addAdmin", "removeAdmin"]:
        return (
            f"{status} workspace admin privileges to {target}"
            f" in workspace {workspace} by {actor}"
        )
    group = extract_group_identifier(event)
    return (
        f"{status} admin group membership ({group}) to {target}"
        f" in workspace {workspace} by {actor}"
    )


def dedup(event):
    target_principal = extract_target_principal(event) or "unknown"
    workspace = event.get("workspaceId", "unknown")
    return f"workspace_admin_privilege_{workspace}_{target_principal}"


def alert_context(event):
    target_principal = extract_target_principal(event)
    principal_type = get_principal_type(target_principal) if target_principal else "Unknown"
    group = extract_group_identifier(event)

    return databricks_alert_context(
        event,
        additional_fields={
            "privilege_scope": "WORKSPACE_LEVEL",
            "target_principal": target_principal,
            "principal_type": principal_type,
            "target_group": group,
            "is_system_admins_group": group.lower() == "admins" if group else False,
            "detection_note": (
                "Direct grants only - nested group resolution requires correlation rule"
            ),
        },
    )
