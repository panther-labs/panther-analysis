def rule(event):
    return event.get('event_type') == 'DOWNLOAD'


def title(event):
    message = ('User [{}] exceeded threshold for number ' +
               'of downloads in the configured time frame.')
    return message.format(
        event.get('created_by', {}).get('login', '<UNKNOWN_USER>'))
