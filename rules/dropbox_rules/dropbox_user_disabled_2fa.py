from panther_base_helpers import deep_get


def rule(event):
    return all(
        [
            deep_get(event, "details", ".tag", default="") == "tfa_change_status_details",
            deep_get(event, "details", "new_value", ".tag") == "disabled",
        ]
    )


def title(event):
    actor = deep_get(event, "actor", "user", "email", default="<EMAIL_NOT_FOUND>")
    target = deep_get(event, "context", "email", default="<TARGET_NOT_FOUND>")
    return f"Dropbox: [{actor}] disabled 2FA for [{target}]."
