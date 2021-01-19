from panther_base_helpers import deep_get

# APPROVED_HOSTS maps AMI IDs to a list of approved dedicated hosts for that AMI.
APPROVED_HOSTS = {
    'EXAMPLE-AMI-ID': ['EXAMPLE-HOST-ID'],
}


def policy(resource):
    # Check if this Instance's AMI is restricted to certain hosts
    if resource.get('ImageId') not in APPROVED_HOSTS:
        return True

    return deep_get(resource, 'Placement',
                    'HostId') in APPROVED_HOSTS[resource.get('ImageId')]
