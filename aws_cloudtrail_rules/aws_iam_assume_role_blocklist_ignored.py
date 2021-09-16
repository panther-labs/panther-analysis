from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get

# This is a list of role ARNs that should not be assumed by users in normal operations
ASSUME_ROLE_BLOCKLIST = [
    "arn:aws:iam::123456789012:role/FullAdminRole",
]


def rule(event):
    # Only considering successful AssumeRole action
    if not aws_cloudtrail_success(event) or event.get("eventName") != "AssumeRole":
        return False

    # Only considering user actions
    if deep_get(event, "userIdentity", "type") not in ["IAMUser", "FederatedUser"]:
        return False

    return deep_get(event, "requestParameters", "roleArn") in ASSUME_ROLE_BLOCKLIST
