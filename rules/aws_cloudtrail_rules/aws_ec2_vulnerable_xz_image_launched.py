from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_iocs import XZ_AMIS

# AMIs published by Fedora between 2024-03-26 and 2024-04-02
# OpenSUSE and Kali do not have any recent [public] AMIs that would be affected


def rule(event):
    if not aws_cloudtrail_success(event) or event.get("eventName") != "RunInstances":
        return False

    amis_launched = event.deep_walk(
        "responseElements",
        "instancesSet",
        "items",
        "imageId",
        default="<AMI ID not found>",
        return_val="all",
    )
    # convert to a list if only one item is returned
    if not isinstance(amis_launched, list):
        amis_launched = [amis_launched]
    if any(ami in XZ_AMIS for ami in amis_launched):
        return True

    return False


def title(event):
    amis_launched = event.deep_walk(
        "responseElements",
        "instancesSet",
        "items",
        "imageId",
        default="<AMI ID not found>",
        return_val="all",
    )
    instance_ids = event.deep_walk(
        "responseElements",
        "instancesSet",
        "items",
        "instanceId",
        default="<Instance ID not found>",
        return_val="all",
    )
    return f"Instance {instance_ids} launched with vulnerable AMI: {amis_launched}"


def alert_context(event):
    return aws_rule_context(event)
