from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "DOWNLOAD"


def title(event):
    message = (
        "User [{}] exceeded threshold for number " + "of downloads in the configured time frame."
    )
    return message.format(deep_get(event, "created_by", "login", default="<UNKNOWN_USER>"))
