def rule(event):
    return "Transferred ownership " in event.deep_get("event_type", "description", default="")


def title(event):
    actor = event.deep_get("actor", "user", "email", default="<EMAIL_NOT_FOUND>")
    previous_owner = event.deep_get(
        "details", "previous_owner_email", default="<PREVIOUS_OWNER_NOT_FOUND>"
    )
    new_owner = event.deep_get("details", "new_owner_email", default="<NEW_OWNER_NOT_FOUND>")
    assets = event.get("assets", [{}])
    asset = [a.get("display_name", "<ASSET_NOT_FOUND>") for a in assets]
    return (
        f"Dropbox: [{actor}] transferred ownership of [{asset}]"
        f"from [{previous_owner}] to [{new_owner}]."
    )


def severity(event):
    new_owner_domain = event.deep_get("details", "new_owner_email", default="@").split("@")[-1]
    previous_owner_domain = event.deep_get("details", "previous_owner_email", default="@").split(
        "@"
    )[-1]

    if new_owner_domain != previous_owner_domain:
        return "DEFAULT"
    return "LOW"
