def rule(event):
    return event.get("status") == "newAlert"


def title(event):
    return f"Microsoft Graph Alert ({event.get('title')})"


def dedup(event):
    return event.get("id")


def severity(event):
    return event.get("severity")


def alert_context(event):
    return {
        "category": event.get("category"),
        "description": event.get("description"),
        "userstates": event.get("userstates", []),
    }
