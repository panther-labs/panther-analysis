def rule(event):
    return (event['userIdentity']['type'] == 'Root' and
            event['userIdentity'].get('invokedBy') is None and
            event['eventType'] != 'AwsServiceEvent')
