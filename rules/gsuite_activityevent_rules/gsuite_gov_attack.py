from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "login":
        return False

    return bool(event.get("name") == "gov_attack_warning")


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
        f"targeted by a government attack"
    )
