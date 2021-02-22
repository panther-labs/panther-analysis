from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    for details in event.get("events", [{}]):
        if details.get("type") == "2sv_change" and details.get("name") == "2sv_disable":
            return True

    return False


def title(event):
    return "Two step verification was disabled for user [{}]".format(
        deep_get(event, "actor", "email", default="<UNKNOWN_USER>")
    )
