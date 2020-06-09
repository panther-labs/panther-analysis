from fnmatch import fnmatch


def rule(event):
    return (fnmatch(event.get('operation'), 'REST.*.OBJECT') and
            ('ciphersuite' not in event or 'tlsVersion' not in event))


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Insecure AWS S3 access to {}'.format(event.get('bucket'))
