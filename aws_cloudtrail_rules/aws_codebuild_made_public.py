from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    return (
        event["eventName"] == "UpdateProjectVisibility"
        and deep_get(event, "requestParameters", "projectVisibility") == "PUBLIC_READ"
    )


def title(event):
    return "AWS CodeBuild Project made Public by {} in account {}".format(
        deep_get(event, "userIdentity", "arn"),
        lookup_aws_account_name(deep_get(event, "recipientAccountId")),
    )
