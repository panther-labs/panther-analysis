def rule(event):
    # Capture DeleteBucket, DeleteBucketPolicy, DeleteBucketWebsite
    return event.get('eventName').startswith('DeleteBucket')


def dedup(event):
    return event.get('userIdentity', {}).get('arn')


def title(event):
    user_identity = event.get('userIdentity', {})
    return '{} {} destroyed a bucket'.format(user_identity.get('type'),
                                             user_identity.get('arn'))
