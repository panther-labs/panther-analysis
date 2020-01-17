def policy(resource):
    # Only check the volumes that are "in-use" and ignore the rest
    if resource['State'] != 'in-use':
        return True

    return bool(resource['Encrypted'])
