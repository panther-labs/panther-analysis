from fnmatch import fnmatch

from panther_aws_helpers import aws_rule_context

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
        event.get("eventSource") == "ecr.amazonaws.com"
        and event.get("eventName") in ECR_CRUD_EVENTS
    ):
        for role in ALLOWED_ROLES:
            if fnmatch(event.deep_get("userIdentity", "arn", default="unknown-arn"), role):
                return False

        return True
    return False


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn', default = 'unknown-arn')}] "
        f"performed ECR {event.get('eventName')} in "
        f"[{event.get('recipientAccountId')} {event.get('awsRegion')}]."
    )


def dedup(event):
    return f"{event.deep_get('userIdentity','arn', default = 'unknown-arn')}"


def alert_context(event):
    return aws_rule_context(event)
