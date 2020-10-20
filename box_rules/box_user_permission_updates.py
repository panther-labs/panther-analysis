def rule(event):
    return (event.get('event_type') == 'CHANGE_FOLDER_PERMISSION' or
            event.get('event_type') == 'ITEM_SHARED_CREATE')


def title(event):
    message = ('User [{}] exceeded threshold for number ' +
               'of permission changes in the configured time frame.')
    return message.format(
        event.get('created_by', {}).get('login', '<UNKNOWN_USER>'))
