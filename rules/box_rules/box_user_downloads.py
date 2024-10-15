def rule(event):
    return event.get("event_type") == "DOWNLOAD"


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] "
        f"exceeded threshold for number of downloads in the configured time frame."
    )
