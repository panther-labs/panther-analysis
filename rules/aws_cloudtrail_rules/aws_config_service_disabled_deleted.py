from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_DISABLE_DELETE_EVENTS = {
    "StopConfigurationRecorder",
    "DeleteDeliveryChannel",
}


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventName") in CONFIG_SERVICE_DISABLE_DELETE_EVENTS
    )


def alert_context(event):
    return aws_rule_context(event)
