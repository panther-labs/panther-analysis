import panther_event_type_helpers as event_type

def get_event_type(event):
    # currently, only tracking a few event types
    if event['eventName'] == 'ConsoleLogin' and event['userIdentity'].get('type') == 'IAMUser':
        if event.get('responseElements', {}).get('ConsoleLogin') == 'Failure':
            return event_type.FAILED_LOGIN
        if event.get('responseElements', {}).get('ConsoleLogin') == 'Success':
            return event_type.SUCCESSFUL_LOGIN
    return None
