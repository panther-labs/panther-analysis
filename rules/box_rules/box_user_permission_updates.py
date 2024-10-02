PERMISSION_UPDATE_EVENT_TYPES = {
    "CHANGE_FOLDER_PERMISSION",
    "ITEM_SHARED_CREATE",
    "ITEM_SHARED",
    "SHARE",
}


def rule(event):
    return event.get("event_type") in PERMISSION_UPDATE_EVENT_TYPES


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}]"
        f" exceeded threshold for number of permission changes in the configured time frame."
    )
