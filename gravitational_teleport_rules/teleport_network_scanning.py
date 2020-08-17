SCAN_COMMANDS = {'arp', 'arp-scan', 'fping', 'nmap'}


def rule(event):
    # Filter to only the session commands
    if event['event'] != 'session.command':
        return False
    # Ignore scan commands without arguments
    if not event.get('argv'):
        return False
    # Check that the program is in our watch list
    return event['program'] in SCAN_COMMANDS


def dedup(event):
    # Group by user and program
    return '{}-{}'.format(event.get('user', 'USER_NOT_FOUND'),
                          event.get('program', 'PROGRAM_NOT_FOUND'))


def title(event):
    return 'User [{}] has issued a network scan with [{}]'.format(
        event.get('user', 'USER_NOT_FOUND'),
        event.get('program', 'PROGRAM_NOT_FOUND'))
