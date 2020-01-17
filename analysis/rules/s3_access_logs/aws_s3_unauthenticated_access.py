# A list of buckets where unauthenticated access is expected
NO_AUTH_BUCKETS = {
    # example-no-auth-bucket,
}


def rule(event):
    if event['bucket'] in NO_AUTH_BUCKETS:
        return False

    return event['requester'] == '-'
