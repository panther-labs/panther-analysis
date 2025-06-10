from typing import Any, Dict


def rule(event: Dict[str, Any]) -> bool:
    tag_keys = set()

    # 1. requestParameters.tagSpecificationSet.items[*].tags
    tag_spec_set = event.deep_get("requestParameters", "tagSpecificationSet", "items", default=[])
    for spec in tag_spec_set:
        for tag in spec.get("tags", []):
            tag_keys.add(tag.get("key"))

    # 2. requestParameters.tagSpecification[*].tags
    tag_spec = event.deep_get("requestParameters", "tagSpecification", default=[])
    for spec in tag_spec:
        for tag in spec.get("tags", []):
            tag_keys.add(tag.get("key"))

    # 3. responseElements.instancesSet.items[*].tagSet.items
    instances = event.deep_get("responseElements", "instancesSet", "items", default=[])
    for instance in instances:
        for tag in instance.get("tagSet", {}).get("items", []):
            tag_keys.add(tag.get("key"))

    # Alert if either required tag is missing
    return not ("team_owner" in tag_keys and "deployment_segment" in tag_keys)


def title(event: Dict[str, Any]) -> str:
    user = event.deep_get("userIdentity", "arn", default="unknown user")
    region = event.get("awsRegion", "unknown region")
    return f"EC2 instance launched without required tags by {user} in {region}"


def runbook(event: Dict[str, Any]) -> str:
    # Try to extract instance ID(s) from the event
    instance_ids = []
    # RunInstances can launch multiple instances, check responseElements.instancesSet.items
    items = event.deep_get("responseElements", "instancesSet", "items", default=[])
    for item in items:
        instance_id = item.get("instanceId")
        if instance_id:
            instance_ids.append(instance_id)
    # Fallback: try requestParameters.instancesSet.items
    if not instance_ids:
        items = event.deep_get("requestParameters", "instancesSet", "items", default=[])
        for item in items:
            instance_id = item.get("instanceId")
            if instance_id:
                instance_ids.append(instance_id)
    instance_id_str = ", ".join(instance_ids) if instance_ids else "unknown"
    event_time = event.get("eventTime", event.get("p_event_time", "unknown time"))
    user = event.deep_get("userIdentity", "arn", default="unknown user")
    return f"""
1. Review related CloudTrail events for the user or automation [{user}] that launched the EC2 instance(s) [{instance_id_str}] in the aws_cloudtrail table around [{event_time}]. Look for other suspicious activity.
2. Confirm if the user or automation connected to the instance(s) by querying the aws_vpcflow table for destination port 22 (SSH) connections to [{instance_id_str}] around [{event_time}].
3. Determine if the launch was expected and if tags were omitted by mistake. If not expected, investigate for possible unauthorized or malicious activity.
4. Tag the instance(s) appropriately or terminate if unauthorized.
"""
