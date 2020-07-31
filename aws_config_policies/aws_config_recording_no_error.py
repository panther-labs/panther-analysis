def policy(resource):
    return resource['Status']['LastErrorCode'] is None
