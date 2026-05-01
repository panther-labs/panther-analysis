from panther_aws_helpers import aws_rule_context


def rule(event):
    return (
        event.get("eventSource") == "sts.amazonaws.com"
        and event.get("eventName") == "GetCallerIdentity"
        and "trufflehog" in event.get("userAgent", "").lower()
    )


def title(event):
    arn = event.deep_get("userIdentity", "arn", default="<unknown>")
    ip_addr = event.get("sourceIPAddress", "<unknown>")
    return f"TruffleHog credential validation detected from [{ip_addr}] as [{arn}]"


def alert_context(event):
    return aws_rule_context(event)
