from panther_base_helpers import deep_get


def policy(resource):
    if not deep_get(resource, 'CredentialReport', 'MfaActive'):
        # MFA is not enabled, this is reported by a different rule
        return True
    return resource['VirtualMFA'] is None
