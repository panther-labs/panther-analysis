from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName", default="") in [
        "ALERT_CONFIG_DISABLED_AUDIT",
        "ALERT_CONFIG_DELETED_AUDIT",
    ]


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    alert_id = event.deep_get("alertConfigId", default="<ALERT_NOT_FOUND>")
    return f"MongoDB: [{user}] has disabled or deleted security alert [{alert_id}]"


def alert_context(event):
    context = mongodb_alert_context(event)
    context["alertConfigId"] = event.deep_get("alertConfigId", default="<ALERT_NOT_FOUND>")
    return context
