from global_filter_snyk import filter_include_event
from panther_base_helpers import deep_get
from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.sso.auth0_connection.create",
    "group.sso.auth0_connection.edit",
    "group.sso.create",
    "group.sso.edit",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "event", default="<NO_EVENT>")
    return action in ACTIONS


def title(event):
    return (
        "Snyk: System SSO Setting event "
        f"[{deep_get(event, 'event', default='<NO_EVENT>')}] "
        f"performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    return snyk_alert_context(event)
