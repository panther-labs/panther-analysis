import panther_event_type_helpers as event_type

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
    permissions = event.deep_get("actionParams", "dynamic", "input", "permissions")
    if permissions is None:
        event.deep_get("actionParams", "input", "permissions", default="")
    role_permissions = set(permissions)

    return (
        len(set(PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
        and event.get("actionResult") == "SUCCEEDED"
    )


def title(event):
    role_name = event.deep_get("actionParams", "dynamic", "input", "name")
    if role_name is None:
        role_name = event.deep_get("actionParams", "input", "name", default="<UNKNOWN ROLE>")
    return (
        f"Role with Admin Permissions created by {event.udm('actor_user')}"
        f"Role Name: {role_name}"
    )


def alert_context(event):
    return {
        "user": event.udm("actor_user"),
        "role_name": event.deep_get("actionParams", "name"),
        "ip": event.udm("source_ip"),
    }
