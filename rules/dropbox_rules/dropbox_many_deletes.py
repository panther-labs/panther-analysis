def rule(event):
    return event.deep_get("event_type", "_tag", default="") == "file_delete"


def title(event):
    user = event.deep_get("actor", "user", "email", default="<UNKNOWN_USER>")
    return f"Dropbox: User [{user}] deleted many files"


def dedup(event):
    return event.deep_get("actor", "user", "email", default="")


def unique(event):
    assets = event.get("assets", [])
    if assets:
        return assets[0].get("path", {}).get("contextual") or None
    return None


def severity(event):
    if event.get("involve_non_team_member", False):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    assets = event.get("assets", [])
    file_path = assets[0].get("path", {}).get("contextual", "") if assets else ""
    return {
        "user": event.deep_get("actor", "user", "email"),
        "file_path": file_path,
        "involve_non_team_member": event.get("involve_non_team_member"),
        "ip_address": event.deep_get("origin", "geo_location", "ip_address"),
    }
