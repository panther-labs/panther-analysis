from panther_base_helpers import IN_PCI_SCOPE, deep_get


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    if not resource["TimeToLiveDescription"]:
        return False

    return deep_get(resource, "TimeToLiveDescription", "TimeToLiveStatus") == "ENABLED"
