from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name
from panther_core import PantherEvent

# Configuration Required
#   Add/remove items from the set below as needed. It should contain instance types which aren't
#   expected to be used in your environment
UNUSUAL_INSTANCE_TYPES = {
    "p2.xlarge"  # Large GPU compute, but no graphics - could be used for crypt mining
}


def rule(event: PantherEvent) -> bool:
    instance_type = event.deep_get("requestParameters", "instanceType")
    return all(
        (
            event.get("eventName") == "RunInstances",
            event.get("eventSource") == "ec2.amazonaws.com",
            instance_type in get_unusual_instance_types(),
        )
    )


def title(event: PantherEvent) -> str:
    # The actor in these events is always AutoScalingService
    account = lookup_aws_account_name(event.get("recipientAccountId"))
    instance_type = event.deep_get("requestParameters", "instanceType")
    return f"EC2 instance with a suspicious type '{instance_type}' was launched in in {account}"


def severity(event: PantherEvent) -> str:
    if not aws_cloudtrail_success(event):
        return "LOW"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["instanceType"] = event.deep_get("requestParameters", "instanceType")
    return context


def get_unusual_instance_types() -> bool:
    # Making this a separate function allows us to mock it during unit tests for reliable testing!
    return UNUSUAL_INSTANCE_TYPES
