from panther_base_helpers import deep_get


def get_resource_tags(event):
    """
    Returns a list of resource tags like pod, cluster, namespace

    Suppressions could allow exceptions for if a string matches any tag
    """
    resource_tags = {}
    for path in [
        ["resource", "labels", "subnetwork_name"],
        ["resource", "labels", "subnetwork_id"],
        ["resource", "labels", "gateway_name"],
        ["resource", "labels", "router_id"],
        ["resource", "labels", "project_id"],
        ["resource", "labels", "region"],
        ["resource", "labels", "location"],
        ["resource", "type"],
    ]:
        value = deep_get(event, *path)
        if value:
            resource_tags[".".join(path)] = value

    return resource_tags
