# Ignore certain operations, users, user agents and specifc iam roles
OPERATIONS = ['REST.GET.', 'REST.HEAD.', 'S3.EXPIRE.OBJECT']
REQUESTERS = ['svc:', 'AmazonS3', ':assumed-role/AWSServiceRole', '']
USERAGENTS = ['aws-internal']
ASSUMED_ROLES = ['assumed-role/pan']

# Optionally, explicitly monitor specific buckets and/or files
BUCKET_NAMES = []
S3_BUCKET_KEY = []

def rule(event):

    # Quick exit if event contains ignored value
    if event.get('operation') in OPERATIONS:
        return False

    if event.get('requester') in REQUESTERS:
        return False

    if event.get('useragent') in USERAGENTS:
        return False

    if event.get('requester') in ASSUMED_ROLES:
        return False

    if event.get('bucket') in BUCKET_NAMES or event.get('key') in S3_BUCKET_KEY: 
        return True
    
    return True

def title(event):
    return f"Unexpected requester put [{event.get('key')}] in [{event.get('bucket')}]"

def alert_context(event):
    return {
        'requester': event.get('requester'),
        'bucket': event.get('bucket'),
        'remoteip': event.get('remoteip'),
        'key': event.get('key'),
        'useragent': event.get('useragent')
    }