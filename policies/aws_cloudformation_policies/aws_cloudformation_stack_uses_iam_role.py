def policy(resource):
    # Ignore stack sets as this setting cannot be set on those
    if resource["Name"].startswith("StackSet-"):
        return True

    return resource["RoleARN"] is not None
