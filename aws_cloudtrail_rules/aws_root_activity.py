def rule(event):
    return (event['userIdentity'].get('type') == 'Root' and
            event['userIdentity'].get('invokedBy') is None and
            event['eventType'] != 'AwsServiceEvent' and
            event['eventName'] != 'ConsoleLogin')


def dedup(event):
    return event.get('sourceIPAddress')
