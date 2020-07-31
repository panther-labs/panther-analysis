def rule(event):
    # Only check access key creation events
    if event['eventName'] != 'CreateAccessKey':
        return False

    # Only root can create root access keys
    if event['userIdentity']['type'] != 'Root':
        return False

    # Only alert if the root user is creating an access key for itself
    return event['requestParameters'] is None
