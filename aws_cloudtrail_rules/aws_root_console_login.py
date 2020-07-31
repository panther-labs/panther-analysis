def rule(event):
    # Only check console logins
    if event['eventName'] != 'ConsoleLogin':
        return False

    # Only check root activity
    if event['userIdentity']['type'] != 'Root':
        return False

    # Only alert if the login was a success
    return event['responseElements']['ConsoleLogin'] == 'Success'
