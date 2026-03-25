from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    action = event.get("actionName")
    return action in ("createUser", "addUser", "add")


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    target = event.deep_get("requestParams", "targetUserName", default="Unknown User")
    endpoint = event.deep_get("requestParams", "endpoint", default="")
    source = f" via {endpoint}" if endpoint else ""
    return f"User account created: {target} by {actor}{source}"


def dedup(event):
    target = event.deep_get("requestParams", "targetUserName", default="unknown")
    return f"user_created_{target}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "target_user": event.deep_get("requestParams", "targetUserName"),
            "endpoint": event.deep_get("requestParams", "endpoint"),
        },
    )
