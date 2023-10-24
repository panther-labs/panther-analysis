from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

# The bodies of these actions are quite diverse.
# When projects are added, the logged detail is the sourceOrgId.
# org.project.stop_monitor is logged for individual files
#   that are ignored.


ACTIONS = [
    "org.sast_settings.edit",
    "org.project.attributes.edit",
    "org.project.add",
    "org.project.delete",
    "org.project.edit",
    "org.project.fix_pr.manual_open",
    "org.project.ignore.create",
    "org.project.ignore.delete",
    "org.project.ignore.edit",
    "org.project.monitor",
    "org.project.pr_check.edit",
    "org.project.remove",
    "org.project.settings.delete",
    "org.project.settings.edit",
    "org.project.stop_monitor",
    # AND the equivalent for licenses",
    "org.license_rule.create",
    "org.license_rule.delete",
    "org.license_rule.edit",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    group_or_org = "<GROUP_OR_ORG>"
    operation = "<NO_OPERATION>"
    action = deep_get(event, "event", default="<NO_EVENT>")
    if "." in action:
        group_or_org = action.split(".")[0].title()
        operation = ".".join(action.split(".")[1:]).title()
    return (
        f"Snyk: [{group_or_org}] "
        f"[{operation}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    # merge event in for the alert_context
    a_c.update(event)
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
    if action == "org.project.fix_pr.manual_open":
        return "INFO"
    return "LOW"
