from panther_base_helpers import deep_get, deep_walk, okta_alert_context


def rule(event):
    return event.get(
        "eventType"
    ) == "application.lifecycle.update" and "Pushing user passwords" in deep_get(
        event, "outcome", "reason", default=""
    )


def title(event):
    target = deep_walk(
        event, "target", "alternateId", default="<alternateId-not-found>", return_val="first"
    )
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"extracted cleartext user passwords via SCIM app [{target}]"
    )


def alert_context(event):
    return okta_alert_context(event)
