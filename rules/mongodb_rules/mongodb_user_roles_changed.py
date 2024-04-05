from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName") == "USER_ROLES_CHANGED_AUDIT"


def title(event):
    target_username = event.get("targetUsername", "<USER_NOT_FOUND>")
    org_id = event.get("orgId", "<ORG_NOT_FOUND>")

    return f"MongoDB Atlas: User [{target_username}] roles changed in org [{org_id}]"


def alert_context(event):
    return mongodb_alert_context(event)
