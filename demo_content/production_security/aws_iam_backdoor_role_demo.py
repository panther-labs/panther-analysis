import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from policyuniverse.policy import Policy


def rule(event):
    if not aws_cloudtrail_success(event) or event.get("eventName") != "UpdateAssumeRolePolicy":
        return False

    policy = event.deep_get("requestParameters", "policyDocument", default="{}")

    return Policy(json.loads(policy)).is_internet_accessible()


def alert_context(event):
    return aws_rule_context(event)
