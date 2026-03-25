from panther_databricks_helpers import (
    ADMIN_PRIVILEGE_ACTIONS,
    databricks_alert_context,
    extract_group_identifier,
    extract_target_principal,
    get_principal_type,
    is_admin_privilege_action,
)


def rule(event):
    # Must be account-level event
    if event.get("auditLevel") != "ACCOUNT_LEVEL":
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
    status_code = event.deep_get("response", "statusCode")
    status = "Granted" if status_code == 200 else "Attempted to grant"

    # Check if it's direct admin action or group-based
    if action in ADMIN_PRIVILEGE_ACTIONS["direct"]:
        return f"{status} account admin privileges to {target} by {actor}"
    group = extract_group_identifier(event)
    return f"{status} admin group membership ({group}) to {target} by {actor}"


def dedup(event):
    target_principal = extract_target_principal(event) or "unknown"
    return f"account_admin_privilege_assignment_{target_principal}"


def alert_context(event):
    target_principal = extract_target_principal(event)
    principal_type = get_principal_type(target_principal) if target_principal else "Unknown"

    return databricks_alert_context(
        event,
        additional_fields={
            "privilege_scope": "ACCOUNT_LEVEL",
            "target_principal": target_principal,
            "principal_type": principal_type,
            "target_group": extract_group_identifier(event),
        },
    )
