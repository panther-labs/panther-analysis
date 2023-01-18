from fnmatch import fnmatch

from panther_base_helpers import aws_rule_context, deep_get

ALLOWED_ARNS = ["*ExampleRole*"]


def rule(event):
    if event.get("eventName") == "ModifyInstanceAttribute" and deep_get(
        event, "requestParameters", "userData"
    ):
        identity_arn = deep_get(event, "userIdentity", "arn", default="<arn_not_found>")
        for ALLOWED_ARN in ALLOWED_ARNS:
            if fnmatch(identity_arn, ALLOWED_ARN):
                return False
        return True
    return False


def title(event):
    return (
        f"[{deep_get(event,'userIdentity','arn')}] "
        "modified the startup script for "
        f" [{deep_get(event, 'requestParameters', 'instanceId')}] "
        f"in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"
    )


def dedup(event):
    return deep_get(event, "requestParameters", "instanceId")


def alert_context(event):
    return aws_rule_context(event)
