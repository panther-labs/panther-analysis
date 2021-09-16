from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "groups_enterprise":
        return False

    if event.get("type") == "moderator_action":
        return bool(event.get("name") == "ban_user_with_moderation")

    return False


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] "
        f"banned another user from a group."
    )
