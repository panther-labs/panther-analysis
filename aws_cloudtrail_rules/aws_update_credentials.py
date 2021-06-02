from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get

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
