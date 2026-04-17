def rule(event):
    if event.deep_get("id", "applicationName") != "user_accounts":
        return False

    return bool(event.get("name") == "titanium_unenroll")


def title(event):
    return (
        f"Advanced protection was disabled for user "
        f"[{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
