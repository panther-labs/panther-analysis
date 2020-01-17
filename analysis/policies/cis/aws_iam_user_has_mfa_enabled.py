def policy(resource):
    # If a user is less than 4 hours old, it may not have a credential report generated yet.
    # It will be re-scanned periodically until a credential report is found, at which point this
    # policy will be properly evaluated.
    if not resource['CredentialReport']:
        return True

    return (
        not resource['CredentialReport']['PasswordEnabled'] or
        # Explicit True check to avoid returning NoneType
        resource['CredentialReport']['MfaActive'] is True
    )
