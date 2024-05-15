from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_CREATE_EVENTS = {
    "PutDeliveryChannel",
    "PutConfigurationRecorder",
    "StartConfigurationRecorder",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.udm("event_name") in CONFIG_SERVICE_CREATE_EVENTS


def alert_context(event):
    return aws_rule_context(event)
