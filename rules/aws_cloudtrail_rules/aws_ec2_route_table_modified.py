from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of an EC2 Route Table modification
EC2_RT_MODIFIED_EVENTS = {
    "CreateRoute",
    "CreateRouteTable",
    "ReplaceRoute",
    "ReplaceRouteTableAssociation",
    "DeleteRouteTable",
    "DeleteRoute",
    "DisassociateRouteTable",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in EC2_RT_MODIFIED_EVENTS


def dedup(event):
    return event.get("recipientAccountId")


def alert_context(event):
    return aws_rule_context(event)
