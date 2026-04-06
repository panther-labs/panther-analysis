def rule(event):
    return event.get("name") == "trash"


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"Google Workspace: User [{user}] deleted many documents from Google Drive"


def dedup(event):
    return event.deep_get("actor", "email", default="")


def unique(event):
    return event.deep_get("parameters", "doc_id") or None


def severity(event):
    visibility = event.deep_get("parameters", "visibility", default="")
    if visibility == "shared_externally":
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return {
        "user": event.deep_get("actor", "email"),
        "doc_title": event.deep_get("parameters", "doc_title"),
        "doc_type": event.deep_get("parameters", "doc_type"),
        "visibility": event.deep_get("parameters", "visibility"),
    }
