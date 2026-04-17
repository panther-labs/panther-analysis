def rule(event):
    if event.deep_get("id", "applicationName") != "user_accounts":
        return False

    if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
        return True

    return False


def title(event):
    return (
        f"Two step verification was disabled for user"
        f" [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
    )
