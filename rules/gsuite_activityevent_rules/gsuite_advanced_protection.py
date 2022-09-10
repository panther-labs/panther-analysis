from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    return bool(event.get("name") == "titanium_unenroll")


def title(event):
    return (
        f"Advanced protection was disabled for user "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
