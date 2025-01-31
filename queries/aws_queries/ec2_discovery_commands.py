from panther_aws_helpers import aws_rule_context, lookup_aws_account_name
from panther_core import PantherEvent


def rule(_):
    return True


def title(event: PantherEvent):
    account = lookup_aws_account_name(event.get("recipientAccountId"))
    instance_id = event.deep_get("userIdentity", "arn").split("/")[-1]
    return f"{account}: Multiple Discovery Commands Executed on EC2 Instance '{instance_id}'"


def alert_context(event: PantherEvent):
    return aws_rule_context(event)
