from panther_aws_helpers import aws_rule_context
from panther_default import lookup_aws_account_name


def rule(event):
    return (
        event["eventName"] == "UpdateProjectVisibility"
        and event.deep_get("requestParameters", "projectVisibility") == "PUBLIC_READ"
    )


def title(event):
    return (
        f"AWS CodeBuild Project made Public by {event.deep_get('userIdentity', 'arn')} "
        f"in account {lookup_aws_account_name(event.deep_get('recipientAccountId'))}"
    )


def alert_context(event):
    return aws_rule_context(event)
