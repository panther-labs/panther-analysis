from panther_databricks_helpers import SYSTEM_USERS, databricks_alert_context


def rule(event):
    if event.get("actionName") != "getSecret":
        return False

    # Filter out system users
    user = event.deep_get("userIdentity", "email", default="")
    return user not in SYSTEM_USERS


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"secret_access_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    scope = event.deep_get("requestParams", "scope", default="Unknown Scope")
    return f"Repeated secret access by {user} in scope {scope}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "secret_scope": event.deep_get("requestParams", "scope"),
            "secret_key": event.deep_get("requestParams", "key"),
        },
    )
