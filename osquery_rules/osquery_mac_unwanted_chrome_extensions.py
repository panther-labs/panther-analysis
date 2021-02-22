def rule(event):
    return "unwanted-chrome-extensions" in event.get("name") and event.get("action") == "added"


def title(event):
    return f"Unwanted Chrome extension(s) detected on [{event.get('hostIdentifier')}]"
