from panther_base_helpers import deep_get

DOMAINS = {
    "@example.com",
}


def rule(event):
    # Check that all events are triggered by internal users
    if event.get("event_type") not in ("FAILED_LOGIN", "SHIELD_ALERT"):
        user = event.get("created_by", {})
        # user id 2 indicates an anonymous user
        if user.get("id", "") == "2":
            return True
        return user.get("login") and not any(user.get("login", "").endswith(x) for x in DOMAINS)
    return False


def title(event):
    return (
        f"External user [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] "
        f"triggered a box event."
    )
