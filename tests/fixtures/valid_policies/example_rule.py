IGNORED_USERS = {}


def rule(event):
    if event['UserName'] in IGNORED_USERS:
        return False

    cred_report = event.get('CredentialReport', {})
    if not cred_report:
        return True

    return cred_report.get('PasswordEnabled', False) and cred_report.get(
        'MfaActive', False)
