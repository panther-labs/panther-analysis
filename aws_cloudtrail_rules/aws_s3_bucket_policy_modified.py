# API calls that are indicative of KMS CMK Deletion
S3_POLICY_CHANGE_EVENTS = {
    'PutBucketAcl',
    'PutBucketPolicy',
    'PutBucketCors',
    'PutBucketLifecycle',
    'PutBucketReplication',
    'DeleteBucketPolicy',
    'DeleteBucketCors',
    'DeleteBucketLifecycle',
    'DeleteBucketReplication',
}


def rule(event):
    return event.get(
        'eventName') in S3_POLICY_CHANGE_EVENTS and not event.get('errorCode')


def title(event):
    return 'S3 bucket modified by [{}]'.format(event.get('userIdentity').get('arn'))
