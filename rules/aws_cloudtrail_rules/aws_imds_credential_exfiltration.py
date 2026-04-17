import ipaddress
import re

from panther_aws_helpers import aws_rule_context

# IMDS credentials appear as assumed-role sessions where the session name
# is an EC2 instance ID (i-xxxxxxxxxxxxxxxxx)
INSTANCE_SESSION_PATTERN = re.compile(r":assumed-role/.+/i-[0-9a-f]+$")

# Legitimate internal services and actions that use instance identity
INTERNAL_SOURCES = {"ssm.amazonaws.com"}
INTERNAL_EVENTS = {"RegisterManagedInstance"}
INTERNAL_IPS = {"AWS Internal"}


def _is_private_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def rule(event):
    arn = event.deep_get("userIdentity", "arn", default="")
    if not INSTANCE_SESSION_PATTERN.search(arn):
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
    ip_addr = event.get("sourceIPAddress", "")
    if ip_addr and not _is_private_ip(ip_addr):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return aws_rule_context(event)
