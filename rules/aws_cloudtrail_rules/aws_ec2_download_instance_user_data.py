from panther_aws_helpers import (
    aws_cloudtrail_success,
    aws_regions,
    aws_rule_context,
    lookup_aws_account_name,
)
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    # Panther's Cloud Security Scanning feature triggers false positives
    actor = event.udm("actor_user")
    if (
        any(actor == "PantherAuditRole-" + region for region in aws_regions())
        and event.get("userAgent") == event.get("sourceIPAddress") == "cloudformation.amazonaws.com"
    ):
        return False

    return (
        event.get("eventName") == "DescribeInstanceAttribute"
        and event.deep_get("requestParameters", "attribute") == "userData"
    )


def title(event: PantherEvent) -> str:
    account_id = lookup_aws_account_name(event.get("recipientAccountId", "UNKNOWN AWS ACCOUNT"))
    actor_user = event.udm("actor_user")
    return (
        f"EC2 Instance User Data accessed in bulk by [{actor_user}] in AWS Account [{account_id}]"
    )


def severity(event: PantherEvent) -> str:
    if not aws_cloudtrail_success(event):
        return "LOW"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    return aws_rule_context(event)
