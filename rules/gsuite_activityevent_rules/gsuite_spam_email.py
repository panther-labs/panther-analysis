from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
        return False
    # Exclude domain-level actor
    if "/hd/domain/" in event.deep_get("actor", "email"):
        return False
    return event.deep_get("parameters", "message_info", "is_spam", default=False) is True


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"Surge in spam emails received by user [{user}]"


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
