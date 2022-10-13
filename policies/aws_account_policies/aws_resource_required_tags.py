# REQUIRED_TAGS_MAPPINGS maps resource types to a set of tag keys required for that resource.
# Example: REQUIRED_TAGS_MAPPINGS = {'AWS.EC2.Instance.Snapshot': {'TagOne', 'TagTwo'}}
# The above example would check all EC2 instances for the presence of tags keyed TagOne and TagTwo
REQUIRED_TAGS_MAPPINGS = {}


def policy(resource):
    if resource["Tags"] is None:
        return True

    # Check if this resource type has any tag requirements.
    # If this resource type doesn't have tag requirements, the policy should be updated.
    if resource["ResourceType"] not in REQUIRED_TAGS_MAPPINGS:
        return False

    required_tags = REQUIRED_TAGS_MAPPINGS[resource["ResourceType"]]
    actual_tags = set(tag["Key"] for tag in resource["Tags"])

    return required_tags.issubset(actual_tags)
