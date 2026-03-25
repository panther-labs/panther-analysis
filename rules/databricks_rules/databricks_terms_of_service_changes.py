from panther_databricks_helpers import databricks_alert_context


def rule(event):
    return event.get("actionName") in ["acceptTos", "sendTos"]


def title(event):
    action = event.get("actionName")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")

    if action == "acceptTos":
        return f"Terms of Service accepted by {actor}"
    return f"Terms of Service distributed by {actor}"


def alert_context(event):
    return databricks_alert_context(event)
