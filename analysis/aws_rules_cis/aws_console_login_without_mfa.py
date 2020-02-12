def rule(event):
    # This rule only applies to ConsoleLogin actions
    if event.get('eventName') != 'ConsoleLogin':
        return False

    # This rule only applies to successful logins
    if event.get('responseElements', {}).get('ConsoleLogin') != 'Success':
        return False

    # Alert if MFA was not used
    return event.get('additionalEventData', {}).get('MFAUsed') == 'No'
