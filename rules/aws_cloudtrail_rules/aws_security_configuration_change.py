from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

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
            event.udm("session_user_name", default=""),
            entry["userName"],
        ):
            if fnmatch(event.udm("event_name"), entry["eventName"]):
                return False

    if event.udm("event_name") == "UpdateDetector":
        return not event.udm("request_enable", default=True)

    return event.udm("event_name") in SECURITY_CONFIG_ACTIONS


def title(event):
    user = event.udm("actor_user") or event.udm("session_user_name")

    return f"Sensitive AWS API call {event.udm('event_name')} made by {user}"


def alert_context(event):
    return aws_rule_context(event)
