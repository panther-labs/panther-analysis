from panther_base_helpers import deep_get

APPROVED_ACTIVE_REGIONS = {
    # 'asia',
    # 'australia',
    # 'eu',
    # 'northamerica',
    # 'southamerica',
    "us",
}


def _resource_in_active_region(location):
    # return False if location is None, meaning the event did not have a location attribute
    # in any of the places we would expect to find one.
    if location is False:
        return False

    return not any(
        (location.startswith(active_region) for active_region in APPROVED_ACTIVE_REGIONS)
    )


def _get_location_or_zone(event):
    resource = event.get("resource")
    if not resource:
        return False

    resource_location = deep_get(resource, "labels", "location")
    if resource_location:
        return resource_location

    resource_zone = deep_get(resource, "labels", "zone")
    if resource_zone:
        return resource_zone

    return False


def rule(event):
    method_name = deep_get(event, "protoPayload", "methodName", default="<UNKNOWN_METHOD>")
    if not method_name.endswith(("insert", "create")):
        return False
    return _resource_in_active_region(_get_location_or_zone(event))


def title(event):
    return (
        f"GCP resource(s) created in unused region/zone in project "
        f"{deep_get(event, 'resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"
    )
