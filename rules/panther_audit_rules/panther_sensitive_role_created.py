import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get

PANTHER_ADMIN_PERMISSIONS = [
    "UserModify",
    "OrganizationAPITokenModify",
    "OrganizationAPITokenRead",
    "GeneralSettingsModify",
]

PANTHER_ROLE_ACTIONS = [
    event_type.USER_GROUP_CREATED,
    event_type.USER_GROUP_MODIFIED,
]


def rule(event):
    if event.udm("event_type") not in PANTHER_ROLE_ACTIONS:
        return False
    role_permissions = set(deep_get(event, "actionParams", "input", "permissions", default=""))

    return (
        len(set(PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
        and event.get("actionResult") == "SUCCEEDED"
    )


def title(event):
    return (
        f"Role with Admin Permissions created by {event.udm('actor_user')}"
        f"Role Name: {deep_get(event, 'actionParams', 'input' ,'name')}"
    )


def alert_context(event):
    return {
        "user": event.udm("actor_user"),
        "role_name": deep_get(event, "actionParams", "name"),
        "ip": event.udm("source_ip"),
    }
