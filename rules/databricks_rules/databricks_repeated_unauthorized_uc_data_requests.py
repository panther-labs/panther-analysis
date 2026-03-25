from panther_databricks_helpers import TEMP_CREDENTIAL_ACTIONS, databricks_alert_context


def rule(event):
    action = event.get("actionName", "")
    status_code = event.deep_get("response", "statusCode")

    # Check for credential generation failures
    if any(cred_action in action for cred_action in TEMP_CREDENTIAL_ACTIONS):
        return status_code in [401, 403]

    # Check for Delta Sharing access failures
    if event.get("serviceName") == "deltaSharingAccess":
        return status_code in [401, 403]

    return False


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"uc_data_unauthorized_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    return f"Repeated unauthorized UC data access attempts by {user}"


def alert_context(event):
    return databricks_alert_context(event)
