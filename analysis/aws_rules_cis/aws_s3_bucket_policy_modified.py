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
    return event.get('eventName') in S3_POLICY_CHANGE_EVENTS
