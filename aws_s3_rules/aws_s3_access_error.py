from panther_base_helpers import pattern_match

# https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
HTTP_STATUS_CODES_TO_MONITOR = {
    403,  # Forbidden
    405,  # Method Not Allowed
}


def rule(event):
    if event.get('useragent', '').startswith('aws-internal'):
        return False

    return (pattern_match(event.get('operation', ''), 'REST.*.OBJECT') and
            event.get('httpstatus') in HTTP_STATUS_CODES_TO_MONITOR)


def title(event):
    return '{status} errors found to S3 Bucket [{bucket}]'.format(
        status=event.get('httpstatus'), bucket=event.get('bucket'))
