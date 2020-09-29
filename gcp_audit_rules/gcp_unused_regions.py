APPROVED_ACTIVE_REGIONS = {
    # 'asia',
    # 'australia',
    # 'eu',
    # 'northamerica',
    # 'southamerica',
    'us',
}


def _resource_in_active_region(location):
    return not any([
        location.startswith(active_region)
        for active_region in APPROVED_ACTIVE_REGIONS
    ])


def _get_location_or_zone(event):
    resource = event.get('resource')
    if not resource:
        return False

    resource_location = resource['labels'].get('location')
    if resource_location:
        return resource_location

    resource_zone = resource['labels'].get('zone')
    if resource_zone:
        return resource_zone

    return False


def rule(event):
    method_name = event['protoPayload'].get('methodName')
    if not (method_name.endswith('.insert') or method_name.endswith('.create')):
        return False
    return _resource_in_active_region(_get_location_or_zone(event))


def title(event):
    return 'GCP resource(s) created in unused region/zone in project {}'.format(
        event['resource'].get('labels', {}).get('project_id',
                                                '<PROJECT_NOT_FOUND>'))
