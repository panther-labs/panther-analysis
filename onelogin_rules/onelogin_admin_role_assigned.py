def rule(event):
    # event_type_id 72 is permissions assigned
    return event.get('event_type_id') == 72 and event.get(
        'privilege_name') == 'Super user'


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    return '[{}] assigned super user permissions to [{}]'.format(
        event.get('actor_user_name', '<UNKNOWN_USER>'),
        event.get('user_name', '<UNKNOWN_USER>'))
