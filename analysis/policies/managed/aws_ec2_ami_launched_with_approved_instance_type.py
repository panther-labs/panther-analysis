# APPROVED_TYPES maps AMI IDs to a list of approved types for that AMI.
APPROVED_TYPES = {
    'EXAMPLE-AMI-ID': ['t2.small'],
}


def policy(resource):
    # Check if this Instance's AMI is restricted to certain instance types
    if resource['ImageId'] not in APPROVED_TYPES:
        return True

    return resource['InstanceType'] in APPROVED_TYPES[resource['ImageId']]
