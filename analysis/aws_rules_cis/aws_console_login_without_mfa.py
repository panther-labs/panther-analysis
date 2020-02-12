def rule(event):
    # This rule only applies to ConsoleLogin actions
    if event['eventName'] != 'ConsoleLogin':
        return False

    # This rule only applies to successful logins
    if event['responseElements']['ConsoleLogin'] != 'Success':
        return False

    # Alert if MFA was not used
    return event['additionalEventData']['MFAUsed'] == 'No'
