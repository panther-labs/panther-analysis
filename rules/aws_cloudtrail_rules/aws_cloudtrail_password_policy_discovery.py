from panther_base_helpers import aws_rule_context

PASSWORD_DISCOVERY_EVENTS = [
    "GetAccountPasswordPolicy",
    "UpdateAccountPasswordPolicy",
    "PutAccountPasswordPolicy",
]


def rule(event):
    service_event = event.udm("log_event_type") == "AwsServiceEvent"
    return event.udm("event_name") in PASSWORD_DISCOVERY_EVENTS and not service_event


def title(event):
    user_arn = event.udm("user_arn")
    return f"Password Policy Discovery detected in AWS CloudTrail from [{user_arn}]"


def alert_context(event):
    return aws_rule_context(event)
