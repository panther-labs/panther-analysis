import json
from fnmatch import fnmatch
from unittest.mock import MagicMock

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
    # {"userName": "ExampleUser", "eventName": "DeleteRule"},
]


def rule(event):
    global ALLOW_LIST  # pylint: disable=global-statement
    if isinstance(ALLOW_LIST, MagicMock):
        ALLOW_LIST = json.loads(ALLOW_LIST())  # pylint: disable=not-callable

    if not aws_cloudtrail_success(event):
        return False

    for entry in ALLOW_LIST:
        if fnmatch(
            event.deep_get(
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
        return not event.deep_get("requestParameters", "enable", default=True)

    return event.get("eventName") in SECURITY_CONFIG_ACTIONS


def title(event):
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )

    return f"Sensitive AWS API call {event.get('eventName')} made by {user}"


def alert_context(event):
    return aws_rule_context(event)
