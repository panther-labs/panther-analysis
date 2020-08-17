def rule(event):
    return bool(event.get('error'))


def dedup(event):
    return event.get('user')


def title(event):
    return 'A high volume of SSH errors was detected from user [{}]'.format(
        event.get('user', 'USER_NOT_FOUND'))
