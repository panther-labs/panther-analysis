def policy(resource):
    # On nested stacks, this can only be set on the root stack
    if resource["RootId"] is not None:
        return True

    return resource["EnableTerminationProtection"] is True
