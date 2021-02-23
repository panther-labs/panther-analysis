MINIMUM_TAGS = 1


def policy(resource):
    if resource["Tags"] is None:
        return False

    return len(resource["Tags"]) >= MINIMUM_TAGS
