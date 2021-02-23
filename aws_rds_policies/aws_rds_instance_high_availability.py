def policy(resource):
    if resource["MultiAZ"] is False and resource["StorageType"] == "aurora":
        return True

    # Explict check for True to avoid returning NoneType
    return resource["MultiAZ"] is True
