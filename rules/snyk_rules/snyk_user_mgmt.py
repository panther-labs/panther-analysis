from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.user.add",
    "group.user.provision.accept",
    "group.user.provision.create",
    "group.user.provision.delete",
    "group.user.remove",
    "org.user.add",
    "org.user.invite",
    "org.user.invite.accept",
    "org.user.invite.revoke",
    "org.user.invite_link.accept",
    "org.user.invite_link.create",
    "org.user.invite_link.revoke",
    "org.user.leave",
    "org.user.provision.accept",
    "org.user.provision.create",
    "org.user.provision.delete",
    "org.user.remove",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    # for org.user.add/group.user.add via SAML/SCIM
    # the attributes .userId and .content.publicUserId
    # have the same value
    if action.endswith(".user.add"):
        target_user = deep_get(event, "content", "userPublicId", default="<NO_CONTENT_UID>")
        actor = deep_get(event, "userId", default="<NO_USERID>")
        if target_user == actor:
            return False
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    operation = "<NO_OPERATION>"
    action = deep_get(event, "event", default="<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
        operation = ".".join(action.split(".")[2:]).title()
    return (
        f"Snyk: [{group_or_org}] User "
        f"[{operation}] "
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
    role = deep_get(event, "content", "after", "role", default=None)
    if not role and "afterRoleName" in deep_get(event, "content", default={}):
        role = deep_get(event, "content", "afterRoleName", default=None)
    if role == "ADMIN":
        return "CRITICAL"
    return "MEDIUM"
