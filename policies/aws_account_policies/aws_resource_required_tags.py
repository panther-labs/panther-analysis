# REQUIRED_TAGS_MAPPINGS maps resource types to a set of tag keys required for that resource.
# Example: REQUIRED_TAGS_MAPPINGS = {'AWS.EC2.Instance.Snapshot': {'Owner', 'CreatedBy'}}
# The above example would check all EC2 instances for the presence of tags keyed TagOne and TagTwo
REQUIRED_TAGS_MAPPINGS = {
    "AWS.EC2.Instance": {"Owner", "CreatedBy"}  # Example. Do not use in production
}


def policy(resource):
    if resource["ResourceType"] in REQUIRED_TAGS_MAPPINGS:
        required_tags = REQUIRED_TAGS_MAPPINGS[resource.get("ResourceType")]
        tags = resource.get("Tags")
        if not tags:
            tags = {}
        actual_tags = tags.keys()
        return required_tags.issubset(actual_tags)
    return True
