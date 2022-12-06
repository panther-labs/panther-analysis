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
    return (
        f"The user account "
        f"{deep_get(event, 'actionParams', 'dynamic', 'input', 'email', default='<UNKNOWN_USER>')}"
        f" was modified by {event.udm('actor_user')}"
    )


def alert_context(event):
    return {
        "user": event.udm("actor_user"),
        "change_target": deep_get(
            event, "actionParams", "dynamic", "input", "email", default="<UNKNOWN_USER>"
        ),
        "ip": event.udm("source_ip"),
    }
