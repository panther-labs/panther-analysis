def rule(event):
    # Capture DeleteBucket, DeleteBucketPolicy, DeleteBucketWebsite
    return event.get('eventName').startswith('DeleteBucket')

def dedup(event):
    return event.get('userIdentity', {}).get('arn')
