def policy(resource):
    return resource['KmsKeyId'] is not None
