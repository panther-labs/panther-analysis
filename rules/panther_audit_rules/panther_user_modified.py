import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get

PANTHER_USER_ACTIONS = [
    event_type.USER_ACCOUNT_MODIFIED,
]


def rule(event):
    if event.udm("event_type") not in PANTHER_USER_ACTIONS:
        return False
    return event.get("actionResult") == "SUCCEEDED"


def title(event):
    change_target = deep_get(event, "actionParams", "dynamic", "input", "email")
    if change_target is None:
        change_target = deep_get(event, "actionParams", "input", "email", default="<UNKNOWN_USER>")
    return f"The user account " f"{change_target} " f"was modified by {event.udm('actor_user')}"


def alert_context(event):
    change_target = deep_get(event, "actionParams", "dynamic", "input", "email")
    if change_target is None:
        change_target = deep_get(event, "actionParams", "input", "email", default="<UNKNOWN_USER>")
    return {
        "user": event.udm("actor_user"),
        "change_target": change_target,
        "ip": event.udm("source_ip"),
    }


def severity(event):
    user = event.udm("actor_user")
    if user is None:
        user = "<NO_PANTHER_USER>"
    if user == "scim":
        return "INFO"
    return "HIGH"
