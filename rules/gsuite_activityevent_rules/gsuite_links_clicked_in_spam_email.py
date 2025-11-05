from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
        return False
    return event.deep_get(
        "parameters", "message_info", "is_spam", default=False
    ) is True and event.deep_get("parameters", "event_info", "mail_event_type", default=0) in (
        15,
        16,
    )


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"[{user}] has clicked potentially malicious links contained in a spam email"


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
