from panther_default import aws_cloudtrail_success
from panther_base_helpers import aws_rule_context

# API calls that are indicative of an EC2 Network Gateway modification
EC2_GATEWAY_MODIFIED_EVENTS = {
    "CreateCustomerGateway",
    "DeleteCustomerGateway",
    "AttachInternetGateway",
    "CreateInternetGateway",
    "DeleteInternetGateway",
    "DetachInternetGateway",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in EC2_GATEWAY_MODIFIED_EVENTS


def dedup(event):
    return event.get("recipientAccountId")


def alert_context(event):
    return aws_rule_context(event)
