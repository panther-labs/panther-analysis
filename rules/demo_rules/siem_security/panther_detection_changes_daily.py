DETECTION_CHANGE_ACTIONS = [
    # Detection Operations
    "CREATE_DETECTION",
    "UPDATE_DETECTION",
    "DELETE_DETECTION",
    "UPDATE_DETECTION_STATE",
    "CREATE_RULE",
    "UPDATE_RULE_AND_FILTER",
    # Data Model Operations
    "CREATE_DATA_MODEL",
    "UPDATE_DATA_MODEL",
    "DELETE_DATA_MODEL",
    # Global Helper Operations
    "CREATE_GLOBAL_HELPER",
    "UPDATE_GLOBAL_HELPER",
    "DELETE_GLOBAL_HELPER",
    # Detection Pack Operations
    "CREATE_DETECTION_PACK",
    "UPDATE_DETECTION_PACK",
    "DELETE_DETECTION_PACK",
    "CREATE_DETECTION_PACK_SOURCE",
    "UPDATE_DETECTION_PACK_SOURCE",
    "DELETE_DETECTION_PACK_SOURCE",
]


def rule(event):
    return (
        event.get("actionName") in DETECTION_CHANGE_ACTIONS
        and event.get("actionResult") == "SUCCEEDED"
    )


def alert_context(event):
    detection_id = None
    detection_name = None

    if event.deep_get("actionParams", "dynamic", "input", "detections"):
        detections = event.deep_get("actionParams", "dynamic", "input", "detections")
        if isinstance(detections, list) and len(detections) > 0:
            detection_id = detections[0].get("id")
            detection_name = detections[0].get("name")
    elif event.deep_get("actionParams", "input", "detections"):
        detections = event.deep_get("actionParams", "input", "detections")
        if isinstance(detections, list) and len(detections) > 0:
            detection_id = detections[0].get("id")
            detection_name = detections[0].get("name")

    return {
        "action": event.get("actionName"),
        "actor": event.deep_get(
            "actor", "attributes", "email", default=event.deep_get("actor", "id")
        ),
        "actor_type": event.deep_get("actor", "type"),
        "detection_id": detection_id,
        "detection_name": detection_name,
        "source_ip": event.get("sourceIP"),
        "timestamp": event.get("p_event_time"),
        "result": event.get("actionResult"),
        "version": event.get("pantherVersion"),
    }
