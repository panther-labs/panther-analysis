APPROVED_TENANCIES = {'default'}


def policy(resource):
    return resource['Placement']['Tenancy'] in APPROVED_TENANCIES
