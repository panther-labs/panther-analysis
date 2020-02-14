def rule(event):
    # Capture DeleteBucket, DeleteBucketPolicy, DeleteBucketWebsite
    return event.get('eventName').startswith('DeleteBucket')
