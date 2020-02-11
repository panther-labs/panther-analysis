def policy(resource):
    return resource['Monitoring']['State'] != 'disabled'
