import shlex


def rule(event):
    if event['action'] != 'added':
        return False

    if 'shell_history' not in event['name']:
        return False

    #TODO: Extract this into a helper
    command = event['columns'].get('command')
    if not command:
        return False
    command_args = shlex.split(command.replace("'",
                                               "\\'"))  # escape single quotes

    if command_args[0] == 'aws':
        return True

    return False


def dedup(event):
    user = event['columns'].get('username')
    host = event['hostIdentifier']
    return '{}-{}'.format(user, host)


def title(event):
    return 'User [{}] issued sensitive `aws` command on [{}]'.format(
        event['columns'].get('username'), event['hostIdentifier'])
