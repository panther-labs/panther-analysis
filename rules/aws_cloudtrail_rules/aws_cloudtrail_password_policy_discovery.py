from panther_aws_helpers import aws_rule_context

PASSWORD_DISCOVERY_EVENTS = [
    "GetAccountPasswordPolicy",
    "UpdateAccountPasswordPolicy",
    "PutAccountPasswordPolicy",
]


def rule(event):
    service_event = event.get("eventType") == "AwsServiceEvent"
    return event.get("eventName") in PASSWORD_DISCOVERY_EVENTS and not service_event


def title(event):
    user_arn = event.deep_get("useridentity", "arn", default="<MISSING_ARN>")
    return f"Password Policy Discovery detected in AWS CloudTrail from [{user_arn}]"


def alert_context(event):
    return aws_rule_context(event)
