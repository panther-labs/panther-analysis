SUSPICIOUS_COMMANDS = {'nc', 'wget'}


def rule(event):
    if event.get('event') != 'session.command':
        return False
    # Ignore commands without arguments
    if not event.get('argv'):
        return False
    return event.get('program') in SUSPICIOUS_COMMANDS


def title(event):
    return 'User [{}] has executed the command [{}]'.format(
        event.get('user', '<UNKNOWN_USER>'),
        event.get('program', '<UNKNOWN_PROGRAM>'))
