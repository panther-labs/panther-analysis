from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
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
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    crud_operation = "<NO_OPERATION>"
    action = deep_get(event, "event", default="<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
        crud_operation = action.split(".")[-1].title()
    return (
        f"Snyk: [{group_or_org}] Service Account "
        f"[{crud_operation}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    role = deep_get(event, "content", "role", "role", default=None)
    if not role:
        role = deep_get(event, "content", "role", default=None)
    if role:
        a_c["role_permission"] = role
    return a_c


def dedup(event):
    return (
        f"{deep_get(event, 'userId', default='<NO_USERID>')}"
        f"{deep_get(event, 'orgId', default='<NO_ORGID>')}"
        f"{deep_get(event, 'groupId', default='<NO_GROUPID>')}"
        f"{deep_get(event, 'event', default='<NO_EVENT>')}"
    )


def severity(event):
    action = deep_get(event, "event", default="<NO_EVENT>")
    role = deep_get(event, "content", "role", "role", default=None)
    if not role:
        role = deep_get(event, "content", "role", default=None)
    if all(
        [role == "ADMIN", action.endswith((".service_account.create", ".service_account.delete"))]
    ):
        return "CRITICAL"
    if action.endswith((".service_account.create", ".service_account.delete")):
        return "HIGH"
    return "MEDIUM"
