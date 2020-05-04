# Tags: ['AWS Managed Rules - Compute']
APPROVED_HOSTS = {
    'EXAMPLE-HOST-ID',
}


def policy(resource):
    return resource['Placement']['HostId'] in APPROVED_HOSTS
