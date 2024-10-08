from panther_okta_helpers import okta_alert_context


def rule(event):
    return event.get(
        "eventType"
    ) == "application.lifecycle.update" and "Pushing user passwords" in event.deep_get(
        "outcome", "reason", default=""
    )


def title(event):
    target = event.deep_walk(
        "target", "alternateId", default="<alternateId-not-found>", return_val="first"
    )
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"extracted cleartext user passwords via SCIM app [{target}]"
    )


def alert_context(event):
    return okta_alert_context(event)
