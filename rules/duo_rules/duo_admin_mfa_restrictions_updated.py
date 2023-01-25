from panther_duo_helpers import duo_alert_context


def rule(event):
    return event.get("action") == "update_admin_factor_restrictions"


def title(event):
    return "Duo Admin MFA Restrictions Updated " f"by [{event.get('username','<user_not_found>')}]"


def alert_context(event):
    return duo_alert_context(event)
