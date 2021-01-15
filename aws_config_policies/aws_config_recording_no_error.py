from panther_base_helpers import deep_get


def policy(resource):
    return deep_get(resource, 'Status', 'LastErrorCode') is None
