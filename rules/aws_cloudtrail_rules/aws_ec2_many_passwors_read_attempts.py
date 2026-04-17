from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    # Raise alert if this is a GetPasswordData event for an EC2 service
    return (
        event.get("eventName") == "GetPasswordData"
        and event.get("eventSource") == "ec2.amazonaws.com"
    )


def title(event: PantherEvent) -> str:
    actor = event.udm("actor_user")
    return f"{actor} has made multiple requests for EC2 password data in the last hour"


def dedup(event: PantherEvent) -> str:
    # Dedup events based on the principal ID
    return event.udm("actor_user")


def severity(event: PantherEvent) -> str:
    # Return "INFO" severity if the password read attempts are unsuccessful
    if not aws_cloudtrail_success(event):
        return "INFO"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    return aws_rule_context(event)
