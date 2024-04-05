from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName", default="") in ("JOINED_ORG", "REMOVED_FROM_ORG")


def title(event):
    event_name = event.get("eventTypeName")
    target_username = event.get("targetUsername", "<USER_NOT_FOUND>")
    org_id = event.get("orgId", "<ORG_NOT_FOUND>")
    action = "has joined org" if event_name == "JOINED_ORG" else "was removed from org"

    return f"MongoDB Atlas: [{target_username}] {action} [{org_id}]"


def alert_context(event):
    return mongodb_alert_context(event)
