from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success

UPDATE_EVENTS = {"ChangePassword", "CreateAccessKey", "CreateLoginProfile", "CreateUser"}


def rule(event):
    return event.get("eventName") in UPDATE_EVENTS and aws_cloudtrail_success(event)


def dedup(event):
    return deep_get(event, "userIdentity", "userName", default="<UNKNOWN_USER>")


def title(event):
    return (
        f"{deep_get(event, 'userIdentity', 'type')} [{deep_get(event, 'userIdentity', 'arn')}]"
        f" has updated their IAM credentials"
    )


def alert_context(event):
    return aws_rule_context(event)
