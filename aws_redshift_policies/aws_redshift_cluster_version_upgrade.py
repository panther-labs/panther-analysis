def policy(resource):
    # Explicit True check to avoid returning NoneType
    return resource['AllowVersionUpgrade'] is True
