from panther import aws_cloudtrail_success
from panther_base_helpers import aws_rule_context

# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_CREATE_EVENTS = {
    "PutDeliveryChannel",
    "PutConfigurationRecorder",
    "StartConfigurationRecorder",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in CONFIG_SERVICE_CREATE_EVENTS


def alert_context(event):
    return aws_rule_context(event)
