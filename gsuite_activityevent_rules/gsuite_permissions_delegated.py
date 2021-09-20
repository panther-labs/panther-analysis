from panther_base_helpers import deep_get

PERMISSION_DELEGATED_EVENTS = {
    "ASSIGN_ROLE",
}


def rule(event):
    if deep_get(event, "id", "applicationName") != "admin":
        return False
    if event.get("type") == "DELEGATED_ADMIN_SETTINGS":
        return bool(event.get("name") in PERMISSION_DELEGATED_EVENTS)
    return False


def title(event):
    role = deep_get(event, "parameters", "ROLE_NAME")
    user = deep_get(event, "parameters", "USER_EMAIL")
    if not role:
        role = "<UNKNOWN_ROLE>"
    if not user:
        user = "<UNKNOWN_USER>"
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] delegated new"
        f" administrator privileges [{role}] to [{user}]"
    )
