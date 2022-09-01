def policy(resource):
    if resource["PasswordReusePrevention"] is None:
        return False
    return resource["PasswordReusePrevention"] >= 24
