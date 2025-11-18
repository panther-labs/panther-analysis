from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
        return False
    return event.deep_get("parameters", "message_info", "message_set", "type", default=0) == 46


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    subject = event.deep_get("parameters", "message_info", "subject", default="<UNKNOWN_SUBJECT>")
    return (
        f"Message [{subject}] received by user [{user}] "
        f"has bypassed your organization's spam filter"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
