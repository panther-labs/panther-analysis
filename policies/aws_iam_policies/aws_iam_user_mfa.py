from panther_base_helpers import deep_get


def policy(resource):
    # If password logins are disabled, we don't need to worry about MFA
    if not deep_get(resource, "CredentialReport", "PasswordEnabled"):
        return True

    # Explicit True check to avoid returning NoneType
    return deep_get(resource, "CredentialReport", "MfaActive") is True
