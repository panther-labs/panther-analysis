PRIVILEGED_ACTIONS = {
    "EXECUTE_DATA_LAKE_QUERY",
    "UPDATE_ALERT_ASSIGNEE",
    "UPDATE_ALERT_STATUS",
}

def rule(event):
    """Detect privileged actions by Jack-API."""
    return (
        event.get("actor", {}).get("name") == "Jack-API"
        and event.get("actionName") in PRIVILEGED_ACTIONS
        and event.get("actionResult") == "SUCCEEDED"
    )

def title(event):
    return f"Jack-API Privileged Action: {event.get('actionName')} from {event.get('sourceIP')}"

def alert_context(event):
    return {
        "actionName": event.get("actionName"),
        "sourceIP": event.get("sourceIP"),
        "timestamp": event.get("timestamp"),
        "actor_id": event.get("actor", {}).get("id"),
    }

def dedup(event):
    return f"{event.get('actionName')}:{event.get('sourceIP')}" 
