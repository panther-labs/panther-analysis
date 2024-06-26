from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return event.get("eventType") == "user.session.start" and deep_get(
        event, "securityContext", "isProxy", default=False
    )


def title(event):
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"attempted to sign-in from anonymizing VPN with domain "
        f"[{deep_get(event, 'securityContext', 'domain', default='<domain-not-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)


def severity(event):
    # If the user is using Apple Private Relay, demote the severity to INFO
    if (
        event.deep_get("p_enrichment", "ipinfo_privacy", "client.ipAddress", "service")
        == "Apple Private Relay"
    ):
        return "INFO"
    # Return Medium by default
    return "MEDIUM"
