from panther_okta_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == "user.session.start" and event.deep_get(
        "securityContext", "isProxy", default=False
    )


def title(event):
    ip_context = {}
    client = event.get("client", default={})
    security_context = event.get("securityContext", default={})
    if client.get("ipAddress"):
        ip_context["IP"] = client.get("ipAddress")
    for key, source_value in [
        {"ASO", security_context.get("asOrg")},
        {"ISP", security_context.get("isp")},
        {"Domain", security_context.get("domain")},
    ]:
        if source_value:
            ip_context[key] = source_value

    if service := event.deep_get("p_enrichment", "ipinfo_privacy", "client.ipAddress", "service"):
        ip_context["Service"] = service

    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"attempted to sign-in from anonymizing VPN - {ip_context}"
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
