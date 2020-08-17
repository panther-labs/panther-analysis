from panther_oss_helpers import pattern_match_list  # pylint: disable=import-error

USER_CREATE_PATTERNS = [
    'chage',  # user password expiry
    'passwd',  # change passwords for users
    'user*',  # create, modify, and delete users
]


def rule(event):
    # Filter the events
    if event['event'] != 'session.command':
        return False
    # Check that the program matches our list above
    return pattern_match_list(event.get('program', ''), USER_CREATE_PATTERNS)


def dedup(event):
    # Group all events by user
    return event.get('user', 'USER_NOT_FOUND')


def title(event):
    return 'User [{}] has manually modified system users'.format(
        event.get('user', 'USER_NOT_FOUND'))
