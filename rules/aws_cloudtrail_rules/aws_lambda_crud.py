from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context, deep_get

LAMBDA_CRUD_EVENTS = {
    "AddPermission",
    "CreateAlias",
    "CreateEventSourceMapping",
    "CreateFunction",
    "DeleteAlias",
    "DeleteEventSourceMapping",
    "DeleteFunction",
    "PublishVersion",
    "RemovePermission",
    "UpdateAlias",
    "UpdateEventSourceMapping",
    "UpdateFunctionCode",
    "UpdateFunctionConfiguration",
}

ALLOWED_ROLES = [
    "*DeployRole",
]


def rule(event):
    if (
        event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") in LAMBDA_CRUD_EVENTS
    ):
        for role in ALLOWED_ROLES:
            if fnmatch(deep_get(event, "userIdentity", "arn", default="unknown-arn"), role):
                return False
        return True
    return False


def title(event):
    return (
        f"[{deep_get(event, 'userIdentity','arn', default = 'unknown-arn')}] "
        f"performed Lambda "
        f"[{event.get('eventName')}] in "
        f"[{event.get('recipientAccountId')} {event.get('awsRegion')}]."
    )


def dedup(event):
    return f"{deep_get(event, 'userIdentity','arn', default = 'unknown-arn')}"


def alert_context(event):
    return aws_rule_context(event)
