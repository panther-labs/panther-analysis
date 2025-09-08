from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.policy.create",
    "group.policy.delete",
    "group.policy.edit",
    "org.policy.edit",
    "org.ignore_policy.edit",
]


def rule(event):

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    policy_type = "<NO_POLICY_TYPE_FOUND>"
    license_or_rule = event.deep_get("content", "after", "configuration", default={})
    if "rules" in license_or_rule:
        policy_type = "security"
    elif "licenses" in license_or_rule:
        policy_type = "license"
    return (
        f"Snyk: System [{policy_type}] Policy Setting event "
        f"[{event.deep_get('event', default='<NO_EVENT>')}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    a_c["policy_type"] = "<NO_POLICY_TYPE_FOUND>"
    license_or_rule = event.deep_get("content", "after", "configuration", default={})
    if "rules" in license_or_rule:
        a_c["policy_type"] = "security"
    elif "licenses" in license_or_rule:
        a_c["policy_type"] = "license"
    return a_c


def dedup(event):
    # Licenses can apply at org or group levels
    return (
        f"{event.deep_get('userId', default='<NO_USERID>')}"
        f"{event.deep_get('orgId', default='<NO_ORGID>')}"
        f"{event.deep_get('groupId', default='<NO_GROUPID>')}"
        f"{event.deep_get('content', 'publicId', default='<NO_PUBLICID>')}"
    )
