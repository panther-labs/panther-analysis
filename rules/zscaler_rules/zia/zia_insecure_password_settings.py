from panther_zscaler_helpers import zia_alert_context, zia_success


def rule(event):
    if not zia_success(event):
        return False
    auth_frequency = event.deep_get(
        "event",
        "postaction",
        "authFrequency",
        default="<AUTH_FREQUENCY_NOT_FOUND>",
    )
    password_expiry = event.deep_get(
        "event",
        "postaction",
        "passwordExpiry",
        default="<PASSWORD_EXPIRY_NOT_FOUND>",
    )
    password_strength = event.deep_get(
        "event",
        "postaction",
        "passwordStrength",
        default="<PASSWORD_STRENGTH_NOT_FOUND>",
    )
    if (
        auth_frequency == "PERMANENT_COOKIE"
        or password_expiry == "NEVER"  # nosec bandit B105
        or password_strength == "NONE"  # nosec bandit B105
    ):
        return True
    return False


def dedup(event):
    return event.deep_get("event", "adminid", default="<ADMIN_ID_NOT_FOUND>")


def title(event):
    return (
        f"[Zscaler.ZIA]: Password settings are insecure for admin with id "
        f"[{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"
    )


def alert_context(event):
    return zia_alert_context(event)
