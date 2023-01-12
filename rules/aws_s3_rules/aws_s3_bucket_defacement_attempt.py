import json
from fnmatch import fnmatch
from unittest.mock import MagicMock

# Ignore certain operations, users, user agents and specifc iam roles
ALWAYS_IGNORE_SETTINGS = {
    "operation": ["REST.GET.*", "REST.HEAD.*", "S3.EXPIRE.OBJECT"],
    # requestor can also hold assumed-roles
    "requester": ["svc:*", "AmazonS3", "*:assumed-role/AWSServiceRole*"],
    # NOTE: S3 web console uses a userAgent that starts with S3Console and contains
    #  "aws-internal" inside the userAgent string. it's important that we glob _after_
    "userAgent": ["aws-internal*"],
    # Set any buckets that you want to ignore in the bucket list
    "bucket": [],
}

# Any items put in ALERT_SETTINGS will cause an alert to raise, provided
# that they do not match the ignore conditions in ALWAYS_IGNORE_SETTINGS
ALERT_SETTINGS = {
    # If there are high-pri buckets, put their names here
    "bucket": [],
    # If there are high-pri bucket keys, put their names here
    "keys": [],
}


def rule(event):
    global ALWAYS_IGNORE_SETTINGS  # pylint: disable=global-statement
    global ALERT_SETTINGS  # pylint: disable=global-statement
    # First we exclude ignored items
    if isinstance(ALWAYS_IGNORE_SETTINGS, MagicMock):
        # pylint: disable=redefined-outer-name,not-callable
        ALWAYS_IGNORE_SETTINGS = json.loads(ALWAYS_IGNORE_SETTINGS())
    for event_key, ignore_values in ALWAYS_IGNORE_SETTINGS.items():
        for ignore_value in ignore_values:
            if fnmatch(event.get(event_key, ""), ignore_value):
                return False

    # Check for explicitly marked ALWAYS_ALERT_SETTINGS
    if isinstance(ALERT_SETTINGS, MagicMock):
        # pylint: disable=redefined-outer-name,not-callable
        ALERT_SETTINGS = json.loads(ALERT_SETTINGS())
    for event_key, alert_values in ALERT_SETTINGS.items():
        for alert_value in alert_values:
            if fnmatch(event.get(event_key, ""), alert_value):
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
