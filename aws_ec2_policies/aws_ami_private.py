APPROVED_OWNERS = [
    'amazon',
    'microsoft',
]


def policy(resource):
    # These are trusted public snapshot distributors, allow
    if resource['ImageOwnerAlias'] in APPROVED_OWNERS:
        return True

    # Ignore AMIs that are not owned by the scanned account
    if resource['AccountId'] != resource['OwnerId']:
        return True

    return not resource['Public']
