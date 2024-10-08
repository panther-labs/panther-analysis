from panther_config import config

DOMAINS = {"@" + domain for domain in config.ORGANIZATION_DOMAINS}


def rule(event):
    # Check that all events are triggered by internal users
    if event.get("event_type") not in ("FAILED_LOGIN", "SHIELD_ALERT"):
        user = event.get("created_by", {})
        # user id 2 indicates an anonymous user
        if user.get("id", "") == "2":
            return True
        return bool(
            user.get("login") and not any(user.get("login", "").endswith(x) for x in DOMAINS)
        )
    return False


def title(event):
    return (
        f"External user [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] "
        f"triggered a box event."
    )
