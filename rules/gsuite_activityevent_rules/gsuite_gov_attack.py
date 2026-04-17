def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False

    return bool(event.get("name") == "gov_attack_warning")


def title(event):
    return (
        f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
        f"targeted by a government attack"
    )
