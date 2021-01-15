from panther_base_helpers import deep_get


def policy(resource):
    return (not deep_get(
        resource, 'CredentialReport', 'PasswordEnabled', default=False) or
            deep_get(resource, 'CredentialReport', 'MfaActive', default=False))
