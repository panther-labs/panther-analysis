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

    if event.deep_get("content", "after", "description") == "No new Code Analysis issues found":
        return False
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
        f"Snyk: [{group_or_org}] "
        f"[{operation}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    a_c = snyk_alert_context(event)
    # merge event in for the alert_context
    a_c.update(event)
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
    if action == "org.project.fix_pr.manual_open":
        return "INFO"
    return "LOW"
