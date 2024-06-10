from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.udm("event_source") == "iam.amazonaws.com"
        and event.udm("event_name") == "CreateAccessKey"
        and (
            not event.udm("user_arn", default="").endswith(
                f"user/{event.udm('access_key_user_name', default='')}"
            )
        )
    )


def title(event):
    return (
        f"[{event.udm('user_arn')}]"
        " created API keys for "
        f"[{event.udm('access_key_user_name', default='')}]"
    )


def dedup(event):
    return f"{event.udm('user_arn')}"


def alert_context(event):
    return aws_rule_context(event)
