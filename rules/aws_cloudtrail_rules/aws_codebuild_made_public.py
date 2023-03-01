from panther_base_helpers import aws_rule_context, deep_get
from panther_default import lookup_aws_account_name


def rule(event):
    return (
        event["eventName"] == "UpdateProjectVisibility"
        and deep_get(event, "requestParameters", "projectVisibility") == "PUBLIC_READ"
    )


def title(event):
    return (
        f"AWS CodeBuild Project made Public by {deep_get(event, 'userIdentity', 'arn')} "
        f"in account {lookup_aws_account_name(deep_get(event, 'recipientAccountId'))}"
    )


def alert_context(event):
    return aws_rule_context(event)
