from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    if (
        event.get("eventTypeName", "") == "NETWORK_PERMISSION_ENTRY_ADDED"
        and event.get("whitelistEntry", "") == "0.0.0.0/0"
    ):
        return True
    return False


def title(event):
    user = event.get("username", "<USER_NOT_FOUND>")
    group_id = event.get("groupId", "<GROUP_NOT_FOUND>")
    return f"MongoDB: [{user}] has allowed access to group [{group_id}] from anywhere"


def alert_context(event):
    context = mongodb_alert_context(event)
    context["groupId"] = event.get("groupId", "<GROUP_NOT_FOUND>")
    return context
