from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    if event.get("actionName") != "delete":
        return False

    # Only match user deletions, not other account-level deletes
    endpoint = event.deep_get("requestParams", "endpoint", default="")
    return (
        "user" in endpoint.lower() or event.deep_get("requestParams", "targetUserName") is not None
    )


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    return "HIGH" if status_code == 200 else "LOW"


def title(event):
    target_user = event.deep_get("requestParams", "targetUserName", default="Unknown User")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Success" if status_code == 200 else "Failed"
    return f"User account deletion {status}: {target_user} by {actor}"


def dedup(event):
    target_user = event.deep_get("requestParams", "targetUserName", default="unknown")
    return f"user_deleted_{target_user}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "target_user": event.deep_get("requestParams", "targetUserName"),
            "endpoint": event.deep_get("requestParams", "endpoint"),
        },
    )
