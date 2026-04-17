from panther_aws_helpers import aws_rule_context
from panther_core import PantherEvent


def rule(_):
    return True


def title(event: PantherEvent):
    account = event.get("recipientAccountId")
    instance_id = event.deep_get("userIdentity", "arn").split("/")[-1]
    return f"{account}: Multiple Discovery Commands Executed on EC2 Instance '{instance_id}'"


def alert_context(event: PantherEvent):
    return aws_rule_context(event)
