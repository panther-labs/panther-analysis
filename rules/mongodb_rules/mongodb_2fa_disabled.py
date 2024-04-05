from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName", default="") == "ORG_TWO_FACTOR_AUTH_OPTIONAL"


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] has disabled 2FA"


def alert_context(event):
    return mongodb_alert_context(event)
