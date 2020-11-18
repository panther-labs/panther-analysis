def rule(event):
    # Only check ModiyImageAttribute events
    if event['eventName'] != 'ModifyImageAttribute':
        return False

    for item in event.get('requestParameters',
                          {}).get('launchPermission',
                                  {}).get('add', {}).get('items', []):
        if item.get('group') == 'all':
            return True

    return False
