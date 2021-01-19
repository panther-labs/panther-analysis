from panther_base_helpers import deep_get

# APPROVED_TENANCIES maps AMI IDs to a list of approved tenancy states for that AMI.
# The possible tenancy states are dedicated, host, and default
APPROVED_TENANCIES = {
    'EXAMPLE-AMI-ID': ['default'],
}


def policy(resource):
    # Check if this Instance's AMI has a required tenancy setting
    if resource['ImageId'] not in APPROVED_TENANCIES:
        return True

    return deep_get(resource, 'Placement',
                    'Tenancy') in APPROVED_TENANCIES[resource['ImageId']]
