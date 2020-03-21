def rule(event):
    return 'errorCode' in event


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Error When Accessing S3 Bucket {}'.format(event.get('bucket'))
