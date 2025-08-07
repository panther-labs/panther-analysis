from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.cloud_config.settings.edit",
    "group.feature_flags.edit",
]


def rule(event):

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    operation = "<NO_OPERATION>"
    action = event.get("event", "<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
        operation = ".".join(action.split(".")[1:]).title()
    return (
        f"Snyk: [{group_or_org}] Setting "
        f"[{operation}] "
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
