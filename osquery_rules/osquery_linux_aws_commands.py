import shlex

PLATFORM_IGNORE_LIST = {'darwin'}


def rule(event):
    if event['action'] != 'added':
        return False

    if 'shell_history' not in event['name']:
        return False

    if event.get('decorations', {}).get('platform') in PLATFORM_IGNORE_LIST:
        return False

    command = event['columns'].get('command')
    if not command:
        return False
    try:
        command_args = shlex.split(command)
    except ValueError:
        # "No escaped character" or "No closing quotation", probably an invalid command
        return False

    if command_args[0] == 'aws':
        return True

    return False


def title(event):
    return 'User [{}] issued an aws-cli command on [{}]'.format(
        event['columns'].get('username'), event['hostIdentifier'])
