def policy(resource):
    for group in resource['SecurityGroups']:
        if group['GroupName'] == 'default':
            return group['IpPermissions'] is None and group[
                'IpPermissionsEgress'] is None
    return False
