from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context

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
        event.udm("event_source") == "lambda.amazonaws.com"
        and event.udm("event_name") in LAMBDA_CRUD_EVENTS
    ):
        for role in ALLOWED_ROLES:
            if fnmatch(event.udm("user_arn", default="unknown-arn"), role):
                return False
        return True
    return False


def title(event):
    return (
        f"[{event.udm('user_arn', default = 'unknown-arn')}] "
        f"performed Lambda "
        f"[{event.udm('event_name')}] in "
        f"[{event.udm('recipient_account_id')} {event.udm('cloud_region')}]."
    )


def dedup(event):
    return f"{event.udm('user_arn', default = 'unknown-arn')}"


def alert_context(event):
    return aws_rule_context(event)
