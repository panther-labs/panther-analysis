from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context

ECR_CRUD_EVENTS = {
    "BatchCheckLayerAvailability",
    "BatchDeleteImage",
    "BatchGetImage",
    "CompleteLayerUpload",
    "CreateRepository",
    "DeleteRepository",
    "DeleteRepositoryPolicy",
    "GetAuthorizationToken",
    "GetDownloadUrlForLayer",
    "GetRepositoryPolicy",
    "InitiateLayerUpload",
    "PutImage",
    "SetRepositoryPolicy",
    "UploadLayerPart",
}

ALLOWED_ROLES = [
    "*DeployRole",
]


def rule(event):
    if (
        event.udm("event_source") == "ecr.amazonaws.com"
        and event.udm("event_name") in ECR_CRUD_EVENTS
    ):
        for role in ALLOWED_ROLES:
            if fnmatch(event.udm("user_arn"), role):
                return False

        return True
    return False


def title(event):
    return (
        f"[{event.udm('user_arn')}] "
        f"performed ECR {event.udm('event_name')} in "
        f"[{event.udm('recipient_account_id')} {event.udm('cloud_region')}]."
    )


def dedup(event):
    return f"{event.udm('user_arn')}"


def alert_context(event):
    return aws_rule_context(event)
