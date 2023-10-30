from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.request_access_settings.edit",
    "org.request_access_settings.edit",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
    action = deep_get(event, "event", default="<NO_EVENT>")
    if "." in action:
        action = action.split(".")[0].title()
    return (
        f"Snyk: [{action}] External Access settings have been modified "
        f"to PermitExternalUsers:[{current_setting}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
    a_c["current_setting"] = current_setting
    return a_c


def dedup(event):
    return (
        f"{deep_get(event, 'userId', default='<NO_USERID>')}"
        f"{deep_get(event, 'orgId', default='<NO_ORGID>')}"
        f"{deep_get(event, 'groupId', default='<NO_GROUPID>')}"
    )


def severity(event):
    current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
    if current_setting:
        return "HIGH"
    return "INFO"
