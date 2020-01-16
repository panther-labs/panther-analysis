def rule(event):
    # This rule only applies to ConsoleLogin actions
    if event['eventName'] != 'ConsoleLogin':
        return False

    # Alert on failed logins
    return event['responseElements']['ConsoleLogin'] != 'Success'
