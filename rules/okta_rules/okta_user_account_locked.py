from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") in ("user.account.lock", "user.account.lock.limit")


def title(event):
    return (
        f"Okta user [{event.get('actor', {}).get('alternateId', '<id-not-found>')}] "
        "has been locked"
    )


def alert_context(event):
    return okta_alert_context(event)
