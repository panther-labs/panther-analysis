from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.policy.create",
    "group.policy.delete",
    "group.policy.edit",
    "org.policy.edit",
    "org.ignore_policy.edit",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    policy_type = "<NO_POLICY_TYPE_FOUND>"
    license_or_rule = deep_get(event, "content", "after", "configuration", default={})
    if "rules" in license_or_rule:
        policy_type = "security"
    elif "licenses" in license_or_rule:
        policy_type = "license"
    return (
        f"Snyk: System [{policy_type}] Policy Setting event "
        f"[{deep_get(event, 'event', default='<NO_EVENT>')}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    a_c["policy_type"] = "<NO_POLICY_TYPE_FOUND>"
    license_or_rule = deep_get(event, "content", "after", "configuration", default={})
    if "rules" in license_or_rule:
        a_c["policy_type"] = "security"
    elif "licenses" in license_or_rule:
        a_c["policy_type"] = "license"
    return a_c


def dedup(event):
    # Licenses can apply at org or group levels
    return (
        f"{deep_get(event, 'userId', default='<NO_USERID>')}"
        f"{deep_get(event, 'orgId', default='<NO_ORGID>')}"
        f"{deep_get(event, 'groupId', default='<NO_GROUPID>')}"
        f"{deep_get(event, 'content', 'publicId', default='<NO_PUBLICID>')}"
    )
