from fnmatch import fnmatch

from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get, aws_rule_context

SECURITY_CONFIG_ACTIONS = {
    "DeleteAccountPublicAccessBlock",
    "DeleteDeliveryChannel",
    "DeleteDetector",
    "DeleteFlowLogs",
    "DeleteRule",
    "DeleteTrail",
    "DisableEbsEncryptionByDefault",
    "DisableRule",
    "StopConfigurationRecorder",
    "StopLogging",
}

ALLOW_LIST = [
    # Add expected events and users here to suppress alerts
    {"userName": "ExampleUser", "eventName": "ExampleEvent"},
]


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    for entry in ALLOW_LIST:
        if fnmatch(
            deep_get(
                event,
                "userIdentity",
                "sessionContext",
                "sessionIssuer",
                "userName",
                default="",
            ),
            entry["userName"],
        ):
            if fnmatch(event.get("eventName"), entry["eventName"]):
                return False

    if event.get("eventName") == "UpdateDetector":
        return not deep_get(event, "requestParameters", "enable", default=True)

    return event.get("eventName") in SECURITY_CONFIG_ACTIONS


def title(event):
    user = deep_get(event, "userIdentity", "userName") or deep_get(
        event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )

    return f"Sensitive AWS API call {event.get('eventName')} made by {user}"


def alert_context(event):
    return aws_rule_context(event)
