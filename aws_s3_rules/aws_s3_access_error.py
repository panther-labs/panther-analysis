from fnmatch import fnmatch

# https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
HTTP_STATUS_CODES_TO_MONITOR = {
    400,  # Bad Request
    403,  # Forbidden
    405,  # Method Not Allowed
}


def rule(event):
    return (fnmatch(event['operation'], 'REST.*.OBJECT') and
            event['httpstatus'] in HTTP_STATUS_CODES_TO_MONITOR and
            event['errorcode'] != 'IncompleteBody'
           )  # This just happens sometimes


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Request errors found to S3 Bucket {}'.format(event.get('bucket'))
