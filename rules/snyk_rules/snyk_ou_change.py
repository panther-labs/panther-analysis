from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.create",
    "group.delete",
    "group.edit",
    "group.feature_flags.edit",
    "group.org.add",
    "group.org.remove",
    "group.settings.edit",
    "group.settings.feature_flag.edit",
    "org.create",
    "org.delete",
    "org.edit",
    "org.settings.feature_flag.edit",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    action = deep_get(event, "event", default="<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
    return (
        f"Snyk: [{group_or_org}] Organizational Unit settings have been modified "
        f"via [{action}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    return snyk_alert_context(event)


def dedup(event):
    return (
        f"{deep_get(event, 'userId', default='<NO_USERID>')}"
        f"{deep_get(event, 'orgId', default='<NO_ORGID>')}"
        f"{deep_get(event, 'groupId', default='<NO_GROUPID>')}"
        f"{deep_get(event, 'event', default='<NO_EVENT>')}"
    )


def severity(event):
    action = deep_get(event, "event", default="<NO_EVENT>")
    if action.endswith((".remove", ".delete")):
        return "HIGH"
    if action.endswith((".edit")):
        return "MEDIUM"
    return "INFO"
