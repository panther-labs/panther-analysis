SUSPICIOUS_COMMANDS = {'nc', 'wget'}


def rule(event):
    if event['event'] != 'session.command':
        return False
    # Ignore commands without arguments
    if not event.get('argv'):
        return False
    return event['program'] in SUSPICIOUS_COMMANDS


def dedup(event):
    return '{}-{}'.format(event.get('user', 'USER_NOT_FOUND'),
                          event.get('program', 'PROGRAM_NOT_FOUND'))


def title(event):
    return 'User [{}] has executed the command [{}]'.format(
        event.get('user', 'USER_NOT_FOUND'),
        event.get('program', 'PROGRAM_NOT_FOUND'))
