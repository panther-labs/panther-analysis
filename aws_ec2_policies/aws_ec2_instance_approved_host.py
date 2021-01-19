from panther_base_helpers import deep_get

# Tags: ['AWS Managed Rules - Compute']
APPROVED_HOSTS = {
    'EXAMPLE-HOST-ID',
}


def policy(resource):
    return deep_get(resource, 'Placement', 'HostId') in APPROVED_HOSTS
