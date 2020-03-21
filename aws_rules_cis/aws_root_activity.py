def rule(event):
    return (event.get('userIdentity', {}).get('type') == 'Root' and
            event.get('userIdentity', {}).get('invokedBy') is None and
            event.get('eventType') != 'AwsServiceEvent')
