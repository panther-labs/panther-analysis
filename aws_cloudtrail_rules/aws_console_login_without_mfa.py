def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and event.get(
        'responseElements', {}).get('ConsoleLogin') == 'Success' and
            event.get('additionalEventData', {}).get('MFAUsed') == 'No')


def dedup(event):
    return event['userIdentity'].get('arn')
