def policy(resource):
    if not resource['CredentialReport']['MfaActive']:
        # MFA is not enabled, this is reported by a different rule
        return True
    return resource['VirtualMFA'] is None
