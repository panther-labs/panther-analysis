from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.get("eventTypeName", "") == "ORG_PUBLIC_API_ACCESS_LIST_NOT_REQUIRED"


def title(event):
    user = event.get("username", "<USER_NOT_FOUND>")
    return f"MongoDB: [{user}] has disabled IP access list for the Atlas Administration API"


def alert_context(event):
    return mongodb_alert_context(event)
