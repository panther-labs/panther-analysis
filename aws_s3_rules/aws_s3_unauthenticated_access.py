# A list of buckets where authenticated access is expected
AUTH_BUCKETS = {'example-bucket'}


def rule(event):
    return event.get('bucket') in AUTH_BUCKETS and 'requester' not in event


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Unauthenticated access to S3 Bucket [{}]'.format(
        event.get('bucket'))
