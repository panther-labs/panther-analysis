from panther_base_helpers import aws_rule_context
from panther_default import lookup_aws_account_name


def rule(event):
    return (
        event.udm("event_name") == "UpdateProjectVisibility"
        and event.udm("project_visibility") == "PUBLIC_READ"
    )


def title(event):
    return (
        f"AWS CodeBuild Project made Public by {event.udm('user_arn')} "
        f"in account {lookup_aws_account_name(event.udm('recipient_account_id'))}"
    )


def alert_context(event):
    return aws_rule_context(event)
