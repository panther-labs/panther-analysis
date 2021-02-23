from panther_base_helpers import deep_get


def policy(resource):
    return bool(deep_get(resource, "RecordingGroup", "AllSupported"))
