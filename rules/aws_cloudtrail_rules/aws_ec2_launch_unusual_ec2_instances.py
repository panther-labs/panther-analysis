from collections.abc import Mapping

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent

# Configuration Required
#   Add/remove items from the set below as needed. It should contain instance types which aren't
#   expected to be used in your environment
UNUSUAL_INSTANCE_TYPES = {
    "p2.xlarge"  # Large GPU compute, but no graphics - could be used for crypt mining
}


def rule(event: PantherEvent) -> bool:
    return (
        event.get("eventSource") == "ec2.amazonaws.com"
        and event.get("eventName") == "RunInstances"
        and get_instance_type(event) in get_unusual_instance_types()
    )


def title(event: PantherEvent) -> str:
    # The actor in these events is always AutoScalingService
    account = event.get("recipientAccountId")
    instance_type = get_instance_type(event)
    return f"EC2 instance with a suspicious type '{instance_type}' was launched in in {account}"


def severity(event: PantherEvent) -> str:
    if not aws_cloudtrail_success(event):
        return "LOW"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["instanceType"] = get_instance_type(event)
    return context


def get_unusual_instance_types() -> set[str]:
    # Making this a separate function allows us to mock it during unit tests for reliable testing!
    return UNUSUAL_INSTANCE_TYPES


def get_instance_type(event: PantherEvent) -> str:
    # Return the type of the instance that was launch
    instance_type = event.deep_get(
        "requestParameters", "instanceType", default="<UNKNOWN INSTANCE TYPE>"
    )
    # instanceType could be a string or a dict
    if isinstance(instance_type, Mapping):
        instance_type = instance_type.get("value", "<UNKNOWN INSTANCE TYPE>")
    return instance_type
