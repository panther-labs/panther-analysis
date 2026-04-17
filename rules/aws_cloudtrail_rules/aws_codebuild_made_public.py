from panther_aws_helpers import aws_rule_context


def rule(event):
    return (
        event["eventName"] == "UpdateProjectVisibility"
        and event.deep_get("requestParameters", "projectVisibility") == "PUBLIC_READ"
    )


def title(event):
    return (
        f"AWS CodeBuild Project made Public by {event.deep_get('userIdentity', 'arn')} "
        f"in account {event.deep_get('recipientAccountId')}"
    )


def alert_context(event):
    return aws_rule_context(event)
