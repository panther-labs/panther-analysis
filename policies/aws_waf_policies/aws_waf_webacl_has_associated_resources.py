def policy(resource):
    # Check if the WebACL has any associated resources
    associations = resource.get("AssociatedResources", [])
    return len(associations) > 0