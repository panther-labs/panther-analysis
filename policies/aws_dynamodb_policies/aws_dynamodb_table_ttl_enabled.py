from panther_base_helpers import deep_get


def policy(resource):

    if not resource["TimeToLiveDescription"]:
        return False

    return deep_get(resource, "TimeToLiveDescription", "TimeToLiveStatus") == "ENABLED"
