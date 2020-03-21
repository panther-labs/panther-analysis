# A list of buckets where unauthenticated access is not expected
AUTH_BUCKETS = {'example-bucket'}


def rule(event):
    if event.get('bucket') not in AUTH_BUCKETS:
        return False

    return 'requester' not in event


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Unauthenticated Access to S3 Bucket  {}'.format(event.get('bucket'))
