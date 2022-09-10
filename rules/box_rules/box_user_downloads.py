from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "DOWNLOAD"


def title(event):
    return (
        f"User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] "
        f"exceeded threshold for number of downloads in the configured time frame."
    )
