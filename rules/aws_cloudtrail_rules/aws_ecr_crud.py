from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context, deep_get

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
            if fnmatch(deep_get(event, "userIdentity", "arn", default="unknown-arn"), role):
                return False

        return True
    return False


def title(event):
    return (
        f"[{deep_get(event, 'userIdentity','arn', default = 'unknown-arn')}] "
        f"performed ECR CRUD Actions in [{event.get('recipientAccountId')}]."
    )


def dedup(event):
    return f"{deep_get(event, 'userIdentity','arn', default = 'unknown-arn')}"


def alert_context(event):
    return aws_rule_context(event)
