from ipaddress import ip_address

from panther import lookup_aws_account_name
from panther_base_helpers import aws_rule_context, deep_get

# service/event patterns to monitor
RECON_ACTIONS = {
    "dynamodb": ["List", "Describe", "Get"],
    "ec2": ["Describe", "Get"],
    "iam": ["List", "Get"],
    "s3": ["List", "Get"],
    "rds": ["Describe", "List"],
}


def rule(event):
    # Filter events
    if event.get("errorCode") != "AccessDenied":
        return False
    if deep_get(event, "userIdentity", "type") != "IAMUser":
        return False

    # Console Activity can easily result in false positives as some pages contain a mix of
    # items that a user may or may not have access to.
    if event.get("userAgent").startswith("aws-internal/3"):
        return False

    # Validate the request came from outside of AWS
    try:
        ip_address(event.get("sourceIPAddress"))
    except ValueError:
        return False

    # Pattern match this event to the recon actions
    for event_source, event_patterns in RECON_ACTIONS.items():
        if event.get("eventSource", "").startswith(event_source) and any(
            event.get("eventName", "").startswith(event_pattern) for event_pattern in event_patterns
        ):
            return True
    return False


def dedup(event):
    return deep_get(event, "userIdentity", "arn")


def title(event):
    user_type = deep_get(event, "userIdentity", "type")
    if user_type == "IAMUser":
        user = deep_get(event, "userIdentity", "userName")
    # root user
    elif user_type == "Root":
        user = user_type
    else:
        user = "<UNKNOWN_USER>"
    return (
        "Reconnaissance activity denied to user "
        f"[{user}] "
        "in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
