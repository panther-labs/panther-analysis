from ipaddress import ip_address

from panther_base_helpers import aws_rule_context
from panther_default import lookup_aws_account_name

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
    if event.udm("error_code") != "AccessDenied":
        return False
    if event.udm("user_type") != "IAMUser":
        return False

    # Console Activity can easily result in false positives as some pages contain a mix of
    # items that a user may or may not have access to.
    if event.udm("user_agent", default="").startswith("aws-internal/3"):
        return False

    # Validate the request came from outside of AWS
    try:
        ip_address(event.udm("source_ip_address"))
    except ValueError:
        return False

    # Pattern match this event to the recon actions
    for event_source, event_patterns in RECON_ACTIONS.items():
        if event.udm("event_source", default="").startswith(event_source) and any(
            event.udm("event_name", default="").startswith(event_pattern)
            for event_pattern in event_patterns
        ):
            return True
    return False


def dedup(event):
    return event.udm("user_arn")


def title(event):
    user_type = event.udm("user_type")
    if user_type == "IAMUser":
        user = event.udm("actor_user")
    # root user
    elif user_type == "Root":
        user = user_type
    else:
        user = "<UNKNOWN_USER>"
    return (
        "Reconnaissance activity denied to user "
        f"[{user}] "
        "in account "
        f"[{lookup_aws_account_name(event.udm('recipient_account_id'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
