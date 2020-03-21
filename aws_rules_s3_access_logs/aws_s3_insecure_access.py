SECURE_BUCKETS = {
    # example-bucket-name,
}


def rule(event):
    return (event['bucket'] in SECURE_BUCKETS and 'ciphersuite' not in event or
            'tlsVersion' not in event)


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Insecure AWS S3 Access on {}'.format(event.get('bucket'))
