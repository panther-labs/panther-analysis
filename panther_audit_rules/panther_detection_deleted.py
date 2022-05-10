from panther_base_helpers import deep_get

PANTHER_DETECTION_DELETE_ACTIONS = [
    "DELETE_DATA_MODEL",
    "DELETE_DETECTION",
    "DELETE_DETECTION_PACK_SOURCE",
    "DELETE_GLOBAL_HELPER",
    "DELETE_LOOKUP_TABLE",
    "DELETE_SAVED_DATA_LAKE_QUERY",
]


def rule(event):
    return (
        event.get("actionName") in PANTHER_DETECTION_DELETE_ACTIONS
        and event.get("actionResult") == "SUCCEEDED"
    )


def title(event):
    return f"Detection Content has been deleted by {event.udm('actor_user')}"


def alert_context(event):
    detections_list = deep_get(event, "actionParams", "input", "detections")
    return {
        "deleted_detections_list": [x.get("id") for x in detections_list],
        "user": event.udm("actor_user"),
        "ip": event.udm("source_ip"),
    }
