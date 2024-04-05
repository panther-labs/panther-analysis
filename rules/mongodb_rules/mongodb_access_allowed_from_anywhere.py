from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    if (
        event.deep_get("eventTypeName", default="") == "NETWORK_PERMISSION_ENTRY_ADDED"
        and event.deep_get("whitelistEntry", default="") == "0.0.0.0/0"
    ):
        return True
    return False


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    group_id = event.deep_get("groupId", default="<GROUP_NOT_FOUND>")
    return f"MongoDB: [{user}] has allowed access to group [{group_id}] from anywhere"


def alert_context(event):
    context = mongodb_alert_context(event)
    context["groupId"] = event.deep_get("groupId", default="<GROUP_NOT_FOUND>")
    return context
