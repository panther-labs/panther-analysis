from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.get("eventTypeName", "") in [
        "ALERT_CONFIG_DISABLED_AUDIT",
        "ALERT_CONFIG_DELETED_AUDIT",
    ]


def title(event):
    user = event.get("username", "<USER_NOT_FOUND>")
    alert_id = event.get("alertConfigId", "<ALERT_NOT_FOUND>")
    return f"MongoDB: [{user}] has disabled or deleted security alert [{alert_id}]"


def alert_context(event):
    context = mongodb_alert_context(event)
    context["alertConfigId"] = event.get("alertConfigId", "<ALERT_NOT_FOUND>")
    return context
