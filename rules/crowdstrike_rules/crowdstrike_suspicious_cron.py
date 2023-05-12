import shlex
from fnmatch import fnmatch

from panther_base_helpers import (
    crowdstrike_detection_alert_context,
    deep_get,
    filter_crowdstrike_fdr_event_type,
    get_crowdstrike_field,
)

SUSPICIOUS_CRON_CMD_ARGS = {
    # Running in unexpected locations
    "/tmp/*",  # nosec
    # Reaching out to the internet
    "curl",
    "dig",
    "http?://*",
    "nc",
    "wget",
}

SUSPICIOUS_CRON_CMDS = {
    # Passing arguments into /bin/sh
    "*|*sh",
    "*sh -c *",
}


def suspicious_cmd_pairs(command):
    return any((fnmatch(command, c) for c in SUSPICIOUS_CRON_CMDS))


def suspicious_cmd_args(command):
    command_args = shlex.split(command.replace("'", "\\'"))  # escape single quotes
    for cmd in command_args:
        if any((fnmatch(cmd, c) for c in SUSPICIOUS_CRON_CMD_ARGS)):
            return True
    return False


def rule(event):
    if filter_crowdstrike_fdr_event_type(event, "ProcessRollup2"):
        return False

    command = deep_get(event, "event", "CommandLine")
    if not command:
        return False

    return any([suspicious_cmd_args(command), suspicious_cmd_pairs(command)])


def title(event):
    # pylint: disable=line-too-long
    return f"Suspicious cron found on aid [{get_crowdstrike_field(event, 'aid', default=''), '<UNKNOWN_HOST>'}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
