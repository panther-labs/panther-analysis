def rule(event):
    # Capture DeleteBucket, DeleteBucketPolicy, DeleteBucketWebsite
    return event['eventName'].startswith(
        'DeleteBucket') and not event.get('errorCode')


def helper_strip_role_session_id(user_identity_arn):
    # The Arn structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split('/')
    if arn_parts:
        return '/'.join(arn_parts[:2])
    return user_identity_arn


def dedup(event):
    user_identity = event['userIdentity']
    if user_identity.get('type') == 'AssumedRole':
        return helper_strip_role_session_id(user_identity.get('arn', ''))
    return user_identity.get('arn')


def title(event):
    user_identity = event['userIdentity']
    return '{} {} destroyed a bucket'.format(user_identity.get('type'),
                                             dedup(event))
