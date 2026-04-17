import re

from panther_aws_helpers import aws_rule_context

# Pattern matching AWS-managed instance roles (IMDS credentials)
INSTANCE_ROLE_PATTERN = re.compile(r":assumed-role/aws:.+")

# Legitimate internal services and actions that use instance identity
INTERNAL_SOURCES = {"ssm.amazonaws.com"}
INTERNAL_EVENTS = {"RegisterManagedInstance"}
INTERNAL_IPS = {"AWS Internal"}


def rule(event):
    arn = event.deep_get("userIdentity", "arn", default="")
    if not INSTANCE_ROLE_PATTERN.search(arn):
        return False
    # Exclude legitimate internal AWS traffic
    if event.get("eventSource") in INTERNAL_SOURCES:
        return False
    if event.get("eventName") in INTERNAL_EVENTS:
        return False
    if event.get("sourceIPAddress") in INTERNAL_IPS:
        return False
    return True


def title(event):
    arn = event.deep_get("userIdentity", "arn", default="<unknown>")
    ip_addr = event.get("sourceIPAddress", "<unknown>")
    action = event.get("eventName", "<unknown>")
    return (
        f"IMDS instance credential [{arn}] used from [{ip_addr}] "
        f"to call [{event.get('eventSource', '')}:{action}]"
    )


def severity(event):
    # Calls from public IPs are more suspicious
    ip_addr = event.get("sourceIPAddress", "")
    if ip_addr and not ip_addr.startswith(("10.", "172.", "192.168.", "AWS Internal")):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return aws_rule_context(event)
