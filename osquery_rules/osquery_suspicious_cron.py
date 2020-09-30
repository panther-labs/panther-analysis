from fnmatch import fnmatch
import shlex

SUSPICIOUS_CRON_CMD_ARGS = {
    # Running in unexpected locations
    '/tmp/*',  #nosec
    # Reaching out to the internet
    'curl',
    'dig',
    'http?://*',
    'nc',
    'wget',
}

SUSPICIOUS_CRON_CMDS = {
    # Passing arguments into /bin/sh
    '*|*sh',
    '*sh -c *'
}


def suspicious_cmd_pairs(command):
    return any([fnmatch(command, c) for c in SUSPICIOUS_CRON_CMDS])


def suspicious_cmd_args(command):
    command_args = shlex.split(command.replace("'",
                                               "\\'"))  # escape single quotes
    for cmd in command_args:
        if any([fnmatch(cmd, c) for c in SUSPICIOUS_CRON_CMD_ARGS]):
            return True
    return False


def rule(event):
    if 'crontab' not in event['name']:
        return False

    command = event['columns'].get('command')
    if not command:
        return False

    return any([suspicious_cmd_args(command), suspicious_cmd_pairs(command)])


def title(event):
    return 'Suspicious cron found on [{}]'.format(event.get('hostIdentifier'))
