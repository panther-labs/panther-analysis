from panther_aws_helpers import aws_cloudtrail_success
from panther_detection_helpers.caching import add_to_string_set, get_string_set

RULE_ID = "AWS.S3.MassExfiltrationDeletion"
TIME_WINDOW_MINUTES = 15

# Thresholds for suspicious activity
THRESHOLDS = {
    "GetObject": 20,  # 20+ downloads in 15 minutes
    "DeleteObject": 15,  # 15+ deletions in 15 minutes
    "DeleteObjects": 5,  # 5+ batch deletions in 15 minutes
}


def rule(event):
    event_name = event.get("eventName")
    if event_name not in THRESHOLDS:
        return False

    if not aws_cloudtrail_success(event):
        return False

    if event.get("eventSource") != "s3.amazonaws.com":
        return False

    # Get user ARN for tracking
    user_arn = event.deep_get("userIdentity", "arn")
    if not user_arn:
        return False

    # Track unique objects acted upon
    bucket = event.deep_get("requestParameters", "bucketName")
    key = event.deep_get("requestParameters", "key")

    if not bucket:
        return False

    # Create unique identifier for this object action
    if key:
        object_id = f"{bucket}/{key}"
    else:
        # For operations without specific key, use requestID
        object_id = event.get("requestID", bucket)

    # Cache key per user and event type
    cache_key = f"{RULE_ID}-{event_name}-{user_arn}"

    # Add to cache with TTL
    ttl = event.event_time_epoch() + (TIME_WINDOW_MINUTES * 60)
    activities = add_to_string_set(cache_key, object_id, ttl)

    # Handle cache response format
    if isinstance(activities, str):
        import json

        try:
            activities = json.loads(activities)
        except (json.JSONDecodeError, TypeError):
            activities = set()

    return len(activities) >= THRESHOLDS[event_name]


def title(event):
    event_name = event.get("eventName")
    user_arn = event.deep_get("userIdentity", "arn")
    bucket = event.deep_get("requestParameters", "bucketName")

    action = "exfiltration" if event_name == "GetObject" else "deletion"
    return f"S3 mass {action} detected from [{user_arn}] on bucket [{bucket}]"


def severity(event):
    event_name = event.get("eventName")

    # Get activity count for severity assessment
    user_arn = event.deep_get("userIdentity", "arn")
    cache_key = f"{RULE_ID}-{event_name}-{user_arn}"
    activities = get_string_set(cache_key)

    if isinstance(activities, str):
        import json

        try:
            activities = json.loads(activities)
        except (json.JSONDecodeError, TypeError):
            activities = set()

    count = len(activities) if activities else 0

    # Dynamic severity based on scale
    if count >= 100:
        return "Critical"
    elif count >= 50:
        return "High"
    elif event_name.startswith("Delete"):
        return "High"  # Deletions are inherently more serious
    else:
        return "Medium"


def alert_context(event):
    event_name = event.get("eventName")
    user_arn = event.deep_get("userIdentity", "arn")

    # Get activity summary
    activity_summary = {}
    for action in THRESHOLDS.keys():
        cache_key = f"{RULE_ID}-{action}-{user_arn}"
        activities = get_string_set(cache_key)

        if isinstance(activities, str):
            import json

            try:
                activities = json.loads(activities)
            except (json.JSONDecodeError, TypeError):
                activities = set()

        activity_summary[f"{action.lower()}_count"] = len(activities) if activities else 0

    # Determine threat indicators
    threat_indicators = []
    if activity_summary.get("getobject_count", 0) >= 20:
        threat_indicators.append("mass_data_exfiltration")
    if activity_summary.get("deleteobject_count", 0) >= 15:
        threat_indicators.append("mass_data_destruction")
    if activity_summary.get("deleteobjects_count", 0) >= 5:
        threat_indicators.append("batch_data_destruction")

    # Check for ransomware pattern (download then delete)
    if (
        activity_summary.get("getobject_count", 0) >= 10
        and activity_summary.get("deleteobject_count", 0) >= 10
    ):
        threat_indicators.append("ransomware_pattern")

    return {
        "triggering_event": event_name,
        "threshold_used": THRESHOLDS.get(event_name),
        "time_window_minutes": TIME_WINDOW_MINUTES,
        "activity_summary": activity_summary,
        "threat_indicators": threat_indicators,
        "target_bucket": event.deep_get("requestParameters", "bucketName"),
        "source_ip": event.get("sourceIPAddress"),
        "user_agent": event.get("userAgent"),
        "actor_arn": user_arn,
    }


def dedup(event):
    # Dedupe by user and bucket to avoid alert spam
    user_arn = event.deep_get("userIdentity", "arn", default="unknown")
    bucket = event.deep_get("requestParameters", "bucketName", default="unknown")
    return f"{user_arn}-{bucket}"
