from panther_base_helpers import deep_get

def rule(event):
    # Only check ModiyImageAttribute events
    if event.get('eventName') != 'ModifyImageAttribute':
        return False

    added_perms = deep_get(
        event,
        'requestParameters', 'launchPermission', 'add', 'items',
        default=[]
    )
    
    for item in added_perms:
        if item.get('group') == 'all':
            return True

    return False
