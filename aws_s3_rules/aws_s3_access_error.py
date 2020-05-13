# https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
HTTP_STATUS_CODES_TO_MONITOR = {
    400, # Bad Request
    403, # Forbidden
    405, # Method Not Allowed
}

def rule(event):
    return event['httpstatus'] in HTTP_STATUS_CODES_TO_MONITOR


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Errors found on requests to S3 Bucket {}'.format(event.get('bucket'))
