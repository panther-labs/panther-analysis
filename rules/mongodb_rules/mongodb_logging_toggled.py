from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName", default="") == "AUDIT_LOG_CONFIGURATION_UPDATED"


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    return f"MongoDB: [{user}] has changed logging configuration."


def alert_context(event):
    return mongodb_alert_context(event)
