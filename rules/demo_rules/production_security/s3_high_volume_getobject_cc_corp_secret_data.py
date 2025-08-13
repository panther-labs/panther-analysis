import json

from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "S3.HighVolumeGetObject.CC.CorpSecretData"
THRESHOLD = 10  # Number of requests to trigger alert
WINDOW_SECONDS = 300  # 5 minutes


def rule(event):
    # Only process S3ServerAccess logs for the target bucket and GetObject operation
    if (
        event.get("bucket") != "corp-secret-data"
        or event.get("operation") != "REST.GET.OBJECT"
        or "cc" not in (event.get("key") or "")
    ):
        return False
    # Use requester and object key as the key for thresholding
    requester = event.get("requester", "unknown")
    key = event.get("key", "unknown")
    cache_key = f"{RULE_ID}:{requester}:{key}"
    count = add_to_string_set(cache_key, event.get("requestid", ""), WINDOW_SECONDS)
    try:
        if isinstance(count, str):
            count = json.loads(count)
    except (ValueError, json.JSONDecodeError) as error:
        print(f"Error parsing count: {error}")
        return False
    return len(count) >= THRESHOLD


def title(event):
    return (
        f"High volume of S3 GetObject requests to objects with 'cc' in name in "
        f"bucket 'corp-secret-data' "
        f"by [{event.get('requester', 'unknown')}]"
    )


def alert_context(event):
    return {
        "bucket": event.get("bucket"),
        "key": event.get("key"),
        "requester": event.get("requester"),
        "remoteip": event.get("remoteip"),
        "useragent": event.get("useragent"),
        "requestid": event.get("requestid"),
        "time": event.get("time"),
        "operation": event.get("operation"),
    }


def runbook(_):
    return (
        "Investigate the requester and object key for signs of data exfiltration or "
        "unauthorized access. "
        "Review the context of the requests, requester identity, and any related activity. "
        "If suspicious, rotate credentials and review bucket/object permissions."
    )
