from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName") != "gmail":
        return False
    return event.deep_get("parameters", "message_info", "is_spam") is True and event.deep_get(
        "parameters", "event_info", "mail_event_type"
    ) in (17, 18, 19)


def title(event):
    user = event.deep_get("actor", "email")
    return f"[{user}] has downloaded potentially malicious attachments from a spam email"


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
