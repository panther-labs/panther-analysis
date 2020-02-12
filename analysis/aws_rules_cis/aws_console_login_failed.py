def rule(event):
    # This rule only applies to ConsoleLogin actions
    if event.get('eventName') != 'ConsoleLogin':
        return False

    # Alert on failed logins
    return event.get('responseElements', {}).get('ConsoleLogin') != 'Success'
