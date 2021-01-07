import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get('eventName') == 'ConsoleLogin' and deep_get(
            event, 'userIdentity', 'type') == 'IAMUser':
        if event.get('responseElements', {}).get('ConsoleLogin') == 'Failure':
            return event_type.FAILED_LOGIN
        if event.get('responseElements', {}).get('ConsoleLogin') == 'Success':
            return event_type.SUCCESSFUL_LOGIN
    return None
