def rule(event):
    if event.deep_get("id", "applicationName") != "groups_enterprise":
        return False

    if event.get("type") == "moderator_action":
        return bool(event.get("name") == "ban_user_with_moderation")

    return False


def title(event):
    return (
        f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] "
        f"banned another user from a group."
    )
