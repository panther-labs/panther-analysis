from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") == "CreateAccessKey"
        and (
            not deep_get(event, "userIdentity", "arn", default="").endswith(
                f"user/{deep_get(event, 'responseElements', 'accessKey', 'userName', default='')}"
            )
        )
    )


def title(event):
    return (
        f"[{deep_get(event,'userIdentity','arn')}]"
        " created API keys for "
        f"[{deep_get(event,'responseElements','accessKey','userName', default = '')}]"
    )


def dedup(event):
    return f"{deep_get(event,'userIdentity','arn')}"


def alert_context(event):
    return aws_rule_context(event)
