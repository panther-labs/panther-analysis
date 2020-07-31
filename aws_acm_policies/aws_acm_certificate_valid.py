def policy(resource):
    if not bool(resource['InUseBy']):
        return True

    return resource['Status'] == 'ISSUED'
