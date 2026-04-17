def policy(resource):

    # Casting to Bool as this may be None and we cannot return a NoneType
    return bool(resource["SSLPolicies"])
