from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.service_account.create",
    "group.service_account.delete",
    "group.service_account.edit",
    "org.service_account.create",
    "org.service_account.delete",
    "org.service_account.edit",
    "org.service_account.membership.upsert",
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
        f"Snyk: [{group_or_org}] Service Account "
        f"[{crud_operation}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    role = event.deep_get("content", "role", "role", default=None)
    if not role:
        role = event.deep_get("content", "role", default=None)
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
    action = event.get("event", "<NO_EVENT>")
    role = event.deep_get("content", "role", "role", default=None)
    if not role:
        role = event.deep_get("content", "role", default=None)
    if all(
        [role == "ADMIN", action.endswith((".service_account.create", ".service_account.delete"))]
    ):
        return "CRITICAL"
    if action.endswith((".service_account.create", ".service_account.delete")):
        return "HIGH"
    return "MEDIUM"
