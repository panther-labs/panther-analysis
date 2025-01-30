from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    return aws_cloudtrail_success(event) and event.get("eventName") == "SendSSHPublicKey"


def title(event: PantherEvent) -> str:
    actor = event.udm("actor_user")
    account_name = lookup_aws_account_name(event.get("recipientAccountId"))
    return f"{actor} uploaded an SSH Key to multiple instances in {account_name}"


def dedup(event: PantherEvent) -> str:
    # Dedup based on the public SSH key
    return event.deep_get("requestParameters", "sSHPublicKey")


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["instanceId"] = event.deep_get(
        "requestParameters", "instanceId", default="<UNKNOWN EC2 INSTANCE ID>"
    )
    return context
