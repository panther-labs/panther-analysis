def rule(event):
    # Filter the events
    if event.get('event') != 'session.command':
        return False
    # Ignore list/read events
    if '-l' in event.get('argv', []):
        return False
    return event.get('program') == 'crontab'


def title(event):
    return 'User [{}] has modified scheduled jobs'.format(
        event.get('user', '<UNKNOWN_USER>'))
