from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
        return True

    return False


def title(event):
    return (
        f"Two step verification was disabled for user"
        f" [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
    )
