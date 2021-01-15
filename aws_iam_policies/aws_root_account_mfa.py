from panther_base_helpers import deep_get


def policy(resource):
    # Explicit check for True as the value may be None, and we want to return a bool not a NoneType
    return deep_get(resource, 'CredentialReport', 'MfaActive') is True
