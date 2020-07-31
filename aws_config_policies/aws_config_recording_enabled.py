def policy(resource):
    return resource['Status']['Recording'] is True
