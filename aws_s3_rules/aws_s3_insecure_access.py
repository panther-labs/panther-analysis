from panther_oss_helpers import pattern_match  # pylint: disable=import-error


def rule(event):
    return (pattern_match(event.get('operation'), 'REST.*.OBJECT') and
            ('ciphersuite' not in event or 'tlsVersion' not in event))


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Insecure access to S3 Bucket [{}]'.format(event.get('bucket'))
