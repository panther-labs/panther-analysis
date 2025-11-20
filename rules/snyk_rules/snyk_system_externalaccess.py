from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.request_access_settings.edit",
    "org.request_access_settings.edit",
]


def rule(event):

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    current_setting = event.deep_get("content", "after", "isEnabled", default=False)
    action = event.get("event", "<NO_EVENT>")
    if "." in action:
        action = action.split(".")[0].title()
    return (
        f"Snyk: [{action}] External Access settings have been modified "
        f"to PermitExternalUsers:[{current_setting}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    current_setting = event.deep_get("content", "after", "isEnabled", default=False)
    a_c["current_setting"] = current_setting
    return a_c


def dedup(event):
    return (
        f"{event.deep_get('userId', default='<NO_USERID>')}"
        f"{event.deep_get('orgId', default='<NO_ORGID>')}"
        f"{event.deep_get('groupId', default='<NO_GROUPID>')}"
    )


def severity(event):
    current_setting = event.deep_get("content", "after", "isEnabled", default=False)
    if current_setting:
        return "HIGH"
    return "INFO"
