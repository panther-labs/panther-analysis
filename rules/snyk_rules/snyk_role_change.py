from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.role.create",
    "group.role.edit",
    "group.user.role.create",
    "group.user.role.delete",
    "group.user.role.edit",
    "org.user.role.create",
    "org.user.role.delete",
    "org.user.role.details.edit",
    "org.user.role.edit",
    "org.user.role.permissions.edit",
]


def rule(event):

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    crud_operation = "<NO_OPERATION>"
    action = event.get("event", "<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
        crud_operation = action.split(".")[-1].title()
    return (
        f"Snyk: [{group_or_org}] Role "
        f"[{crud_operation}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    role = event.deep_get("content", "after", "role", default=None)
    if not role and "afterRoleName" in event.get("content", {}):
        role = event.deep_get("content", "afterRoleName", default=None)
    if role:
        a_c["role_permission"] = role
    return a_c


def dedup(event):
    return (
        f"{event.deep_get('userId', default='<NO_USERID>')}"
        f"{event.deep_get('orgId', default='<NO_ORGID>')}"
        f"{event.deep_get('groupId', default='<NO_GROUPID>')}"
        f"{event.deep_get('event', default='<NO_EVENT>')}"
    )


def severity(event):
    role = event.deep_get("content", "after", "role", default=None)
    if not role and "afterRoleName" in event.get("content", {}):
        role = event.deep_get("content", "afterRoleName", default=None)
    if role == "ADMIN":
        return "CRITICAL"
    return "MEDIUM"
