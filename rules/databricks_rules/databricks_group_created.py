from panther_databricks_helpers import databricks_alert_context, extract_group_identifier


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    return event.get("actionName") == "createGroup"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    group = extract_group_identifier(event) or event.deep_get(
        "requestParams", "groupName", default="Unknown Group"
    )
    return f"Group created: {group} by {actor}"


def dedup(event):
    group = extract_group_identifier(event) or "unknown"
    return f"group_created_{group}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "group_name": extract_group_identifier(event),
        },
    )
