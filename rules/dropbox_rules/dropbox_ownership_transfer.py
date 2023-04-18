from panther_base_helpers import deep_get


def rule(event):
    return "Transferred ownership " in deep_get(event, "event_type", "description", default="")


def title(event):
    actor = deep_get(event, "actor", "user", "email", default="<EMAIL_NOT_FOUND>")
    previous_owner = deep_get(
        event, "details", "previous_owner_email", default="<PREVIOUS_OWNER_NOT_FOUND>"
    )
    new_owner = deep_get(event, "details", "new_owner_email", default="<NEW_OWNER_NOT_FOUND>")
    assets = event.get("assets", [{}])
    asset = [a.get("display_name", "<ASSET_NOT_FOUND>") for a in assets]
    return f"Dropbox: [{actor}] transferred ownership of [{asset}] from [{previous_owner}] to [{new_owner}]."
