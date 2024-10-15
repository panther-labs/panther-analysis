from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# This is a list of role ARNs that should not be assumed by users in normal operations
ASSUME_ROLE_BLOCKLIST = [
    "arn:aws:iam::123456789012:role/FullAdminRole",
]


def rule(event):
    # Only considering successful AssumeRole action
    if not aws_cloudtrail_success(event) or event.get("eventName") != "AssumeRole":
        return False

    # Only considering user actions
    if event.deep_get("userIdentity", "type") not in ["IAMUser", "FederatedUser"]:
        return False

    return event.deep_get("requestParameters", "roleArn") in ASSUME_ROLE_BLOCKLIST


def alert_context(event):
    return aws_rule_context(event)
