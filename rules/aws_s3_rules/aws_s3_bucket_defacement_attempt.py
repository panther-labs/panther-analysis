from fnmatch import fnmatch

# Ignore certain operations, users, user agents and specifc iam roles
EXCLUDED_OPERATIONS = ["REST.GET.*", "REST.HEAD.*", "S3.EXPIRE.OBJECT"]
EXCLUDED_REQUESTERS = ["svc:*", "AmazonS3", "*:assumed-role/AWSServiceRole*", ""]
EXCLUDED_USERAGENTS = ["*aws-internal*"]
EXCLUDED_ASSUMED_ROLES = ["*assumed-role/pan*"]

# Optionally, explicitly monitor specific buckets and/or files
INCLUDED_BUCKET_NAMES = []
INCLUDED_S3_BUCKET_KEY = []


def rule(event):

    # Quick exit if event contains ignored value
    for item in EXCLUDED_OPERATIONS:
        if fnmatch(event.get("operation"), item):
            return False

    for item in EXCLUDED_REQUESTERS:
        if fnmatch(event.get("requester"), item):
            return False

    for item in EXCLUDED_USERAGENTS:
        if fnmatch(event.get("useragent"), item):
            return False

    for item in EXCLUDED_ASSUMED_ROLES:
        if fnmatch(event.get("requester"), item):
            return False

    for item in INCLUDED_BUCKET_NAMES:
        if fnmatch(event.get("bucket"), item):
            return True

    for item in INCLUDED_S3_BUCKET_KEY:
        if fnmatch(event.get("key"), item):
            return True

    return True


def title(event):
    return f"Unexpected requester put [{event.get('key')}] in [{event.get('bucket')}]"


def alert_context(event):
    return {
        "requester": event.get("requester"),
        "bucket": event.get("bucket"),
        "remoteip": event.get("remoteip"),
        "key": event.get("key"),
        "useragent": event.get("useragent"),
    }
