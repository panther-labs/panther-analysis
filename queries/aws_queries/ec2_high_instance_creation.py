from panther_aws_helpers import aws_rule_context
from panther_core import PantherEvent


def rule(_):
    return True


def title(event: PantherEvent):
    account = event.get("account_id", "Unknown Account")
    region = event.get("region", "Unknown Region")
    total_instances = event.get("total_instances_created", 0)
    user_arn = event.get("user_arn", "Unknown User")

    # Extract a readable user identifier from the ARN
    if user_arn and user_arn != "Unknown User":
        user_id = user_arn.split("/")[-1]
    else:
        user_id = event.get("principal_id", "Unknown")

    return (
        f"{account}: Abnormally High EC2 Instance Creation Detected - "
        f"{total_instances} instances created by {user_id} in {region}"
    )


def severity(event: PantherEvent):
    total_instances = event.get("total_instances_created", 0)

    # Adjust severity based on volume
    if total_instances >= 50:
        return "CRITICAL"
    if total_instances >= 25:
        return "HIGH"
    return "MEDIUM"


def alert_context(event: PantherEvent):
    context = aws_rule_context(event)

    # Add additional context specific to this detection
    context.update({
        "total_instances_created": event.get("total_instances_created"),
        "total_run_instances_calls": event.get("total_run_instances_calls"),
        "instance_types": event.get("instance_types"),
        "distinct_instance_types": event.get("distinct_instance_types"),
        "distinct_amis": event.get("distinct_amis"),
        "time_span_minutes": event.get("time_span_minutes"),
        "first_creation_time": event.get("first_creation_time"),
        "last_creation_time": event.get("last_creation_time"),
        "source_ip": event.get("source_ip"),
        "identity_type": event.get("identity_type"),
    })

    return context
