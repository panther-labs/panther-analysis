def policy(resource):
    # Explict check for True to avoid returning NoneType
    return resource['MultiAZ'] is True and resource['StorageType'] != 'aurora'
