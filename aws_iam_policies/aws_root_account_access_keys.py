from panther_base_helpers import deep_get


def policy(resource):
    return (not deep_get(resource, 'CredentialReport', 'AccessKey1Active') and
            not deep_get(resource, 'CredentialReport', 'AccessKey2Active'))
