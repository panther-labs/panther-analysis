from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    if not resource['TimeToLiveDescription']:
        return False

    return resource['TimeToLiveDescription']['TimeToLiveStatus'] == 'ENABLED'
