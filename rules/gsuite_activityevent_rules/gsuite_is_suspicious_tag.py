def rule(event):
    return event.deep_get("parameters", "is_suspicious") is True


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"A suspicious action was reported for user [{user}]"
