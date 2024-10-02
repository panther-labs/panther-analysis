PERMISSION_DELEGATED_EVENTS = {
    "ASSIGN_ROLE",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "admin":
        return False
    if event.get("type") == "DELEGATED_ADMIN_SETTINGS":
        return bool(event.get("name") in PERMISSION_DELEGATED_EVENTS)
    return False


def title(event):
    role = event.deep_get("parameters", "ROLE_NAME")
    user = event.deep_get("parameters", "USER_EMAIL")
    if not role:
        role = "<UNKNOWN_ROLE>"
    if not user:
        user = "<UNKNOWN_USER>"
    return (
        f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}] delegated new"
        f" administrator privileges [{role}] to [{user}]"
    )
