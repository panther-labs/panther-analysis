from panther import aws_cloudtrail_success

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
