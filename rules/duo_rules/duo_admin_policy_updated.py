from panther_duo_helpers import duo_alert_context


def rule(event):
    return event.get("action") == "policy_update"


def title(event):
    return (
        f"Duo: [{event.get('username', '<username_not_found>')}] "
        f"updated [{event.get('object', 'Duo Policy')}]."
    )


def alert_context(event):
    return duo_alert_context(event)
