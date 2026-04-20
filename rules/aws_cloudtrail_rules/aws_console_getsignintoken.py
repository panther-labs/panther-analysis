from panther_aws_helpers import aws_rule_context

# User agents associated with legitimate AWS SSO portal sign-in token requests
SSO_USER_AGENTS = ["Jersey/${project.version}"]


def rule(event):
    if event.get("eventSource") != "signin.amazonaws.com":
        return False
    if event.get("eventName") != "GetSigninToken":
        return False
    # Exclude legitimate AWS SSO portal traffic
    user_agent = event.get("userAgent", "")
    for sso_ua in SSO_USER_AGENTS:
        if sso_ua in user_agent:
            return False
    return True


def title(event):
    arn = event.deep_get("userIdentity", "arn", default="<unknown>")
    ip_addr = event.get("sourceIPAddress", "<unknown>")
    user_agent = event.get("userAgent", "<unknown>")
    return (
        f"Suspicious GetSigninToken call from [{ip_addr}] "
        f"as [{arn}] with user agent [{user_agent}]"
    )


def alert_context(event):
    return aws_rule_context(event)
