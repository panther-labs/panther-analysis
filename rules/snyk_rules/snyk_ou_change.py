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

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    action = event.get("event", "<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
    return (
        f"Snyk: [{group_or_org}] Organizational Unit settings have been modified "
        f"via [{action}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    return snyk_alert_context(event)


def dedup(event):
    return (
        f"{event.deep_get('userId', default='<NO_USERID>')}"
        f"{event.deep_get('orgId', default='<NO_ORGID>')}"
        f"{event.deep_get('groupId', default='<NO_GROUPID>')}"
        f"{event.deep_get('event', default='<NO_EVENT>')}"
    )


def severity(event):
    action = event.get("event", "<NO_EVENT>")
    if action.endswith((".remove", ".delete")):
        return "HIGH"
    if action.endswith((".edit")):
        return "MEDIUM"
    return "INFO"
