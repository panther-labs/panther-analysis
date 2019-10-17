IGNORED_USERS = {}


def policy(resource):
    if resource['UserName'] in IGNORED_USERS:
        return False

    cred_report = resource.get('CredentialReport', {})
    if not cred_report:
        return True

    return cred_report.get('PasswordEnabled', False) and cred_report.get(
        'MfaActive', False)
