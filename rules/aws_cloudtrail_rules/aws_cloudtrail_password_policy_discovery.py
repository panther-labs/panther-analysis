from panther_base_helpers import aws_rule_context, deep_get

PASSWORD_DISCOVERY_EVENTS = [
    "GetAccountPasswordPolicy",
    "UpdateAccountPasswordPolicy",
    "PutAccountPasswordPolicy",
]


def rule(event):
    service_event = event.get("eventType") == "AwsServiceEvent"
    return event.get("eventName") in PASSWORD_DISCOVERY_EVENTS and not service_event


def title(event):
    user_arn = deep_get(event, "useridentity", "arn", default="<MISSING_ARN>")
    return f"Password Policy Discovery detected in AWS CloudTrail from [{user_arn}]"


def alert_context(event):
    return aws_rule_context(event)
