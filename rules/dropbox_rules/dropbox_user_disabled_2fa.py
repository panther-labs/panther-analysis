def rule(event):
    return all(
        [
            event.deep_get("details", ".tag", default="") == "tfa_change_status_details",
            event.deep_get("details", "new_value", ".tag") == "disabled",
        ]
    )


def title(event):
    actor = event.deep_get("actor", "user", "email", default="<EMAIL_NOT_FOUND>")
    target = event.deep_get("context", "email", default="<TARGET_NOT_FOUND>")
    return f"Dropbox: [{actor}] disabled 2FA for [{target}]."
