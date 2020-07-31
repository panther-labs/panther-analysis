def rule(event):
    # Only check password update changes
    if event['eventName'] != 'PasswordUpdated':
        return False

    # Only check root activity
    if event['userIdentity']['type'] != 'Root':
        return False

    # Only alert if the login was a success
    return event['responseElements']['PasswordUpdated'] == 'Success'
