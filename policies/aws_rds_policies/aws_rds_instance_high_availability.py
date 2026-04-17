def policy(resource):
    if resource["MultiAZ"] is False and resource["StorageType"] == "aurora":
        return True

    # Explicit check for True to avoid returning NoneType
    return resource["MultiAZ"] is True
