from fnmatch import fnmatch
import ast

# Ignore certain operations, users, user agents and specifc iam roles
EXCLUDED_OPERATIONS = ["REST.GET.*", "REST.HEAD.*", "S3.EXPIRE.OBJECT"]
EXCLUDED_REQUESTERS = ["svc:*", "AmazonS3", "*:assumed-role/AWSServiceRole*", ""]
EXCLUDED_USERAGENTS = ["*aws-internal*"]
EXCLUDED_ASSUMED_ROLES = ["*assumed-role/pan*"]

# Optionally, explicitly monitor specific buckets and/or files
# Defined as functions so that we may mock our testing
def get_included_bucket_names():
    included_bucket_names = []
    return included_bucket_names


def get_included_s3_bucket_keys():
    included_s3_bucket_keys = []
    return included_s3_bucket_keys


def rule(event):

    # Exit if event contains ignored value
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

    # Exit if event contains watched values
    # with logic added to support mock tests
    included_bucket_names = get_included_bucket_names()
    included_s3_bucket_keys = get_included_s3_bucket_keys()

    if isinstance(included_bucket_names, str):
        included_bucket_names = ast.literal_eval(included_bucket_names)

    if isinstance(included_s3_bucket_keys, str):
        included_s3_bucket_keys = ast.literal_eval(included_s3_bucket_keys)

    for item in included_bucket_names:
        if fnmatch(event.get("bucket"), item):
            return True

    for item in included_s3_bucket_keys:
        if fnmatch(event.get("key"), item):
            return True

    return False


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
