def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') == 'Root' and
            event.get('responseElements', {}).get('ConsoleLogin') == 'Success')


def dedup(event):
    return event.get('sourceIPAddress')
