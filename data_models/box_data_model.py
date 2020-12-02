import panther_event_type_helpers as event_type


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get('event_type') == 'FAILED_LOGIN':
        return event_type.FAILED_LOGIN
    if event.get('event_type') == 'LOGIN':
        return event_type.SUCCESSFUL_LOGIN
    return None
