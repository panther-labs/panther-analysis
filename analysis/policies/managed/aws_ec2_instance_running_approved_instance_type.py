# Tags: ['AWS Managed Rules - Compute']
APPROVED_INSTANCE_TYPES = {
    't2.small',
}


def policy(resource):
    return resource['InstanceType'] in APPROVED_INSTANCE_TYPES
