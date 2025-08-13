from panther_aws_helpers import aws_cloudtrail_success
from panther_detection_helpers.caching import add_to_string_set, get_string_set

RULE_ID = "AWS.SecretsManager.RetrieveSecrets"
TIME_WINDOW_MINUTES = 10

# Event-specific thresholds for unique secrets/actions
EVENT_THRESHOLDS = {
    "ListSecrets": 2,  # Broad reconnaissance
    "DescribeSecret": 3,  # Targeted investigation
    "GetSecretValue": 5,  # Secret exfiltration
}


def rule(event):
    # Order conditions by selectivity - most restrictive first
    event_name = event.get("eventName")
    if event_name not in EVENT_THRESHOLDS:
        return False

    if not aws_cloudtrail_success(event):
        return False

    user_arn = event.deep_get("userIdentity", "arn")
    if not user_arn:
        return False

    return check_suspicious_activity(event, user_arn, event_name)


def check_suspicious_activity(event, user_arn, event_name):
    """Track unique secrets/actions by event type"""
    threshold = EVENT_THRESHOLDS[event_name]

    if event_name == "ListSecrets":
        # Track list operations by requestID (no specific secret)
        request_id = str(event.get("requestID"))
        if not request_id:
            return False
        activity = request_id

    elif event_name in ["DescribeSecret", "GetSecretValue"]:
        # Track unique secrets being accessed
        secret_id = event.deep_get("requestParameters", "secretId")
        region = event.deep_get("awsRegion")
        if not secret_id:
            return False
        activity = f"{secret_id}-{region}"

    else:
        return False

    cache_key = f"{RULE_ID}-{event_name.lower()}-{user_arn}"

    # Add to cache with TTL
    activities = add_to_string_set(
        cache_key, activity, event.event_time_epoch() + TIME_WINDOW_MINUTES * 60
    )

    # Handle string response from cache
    if isinstance(activities, str):
        import json

        try:
            activities = json.loads(activities)
        except (json.JSONDecodeError, TypeError):
            activities = set()

    return len(activities) >= threshold


def title(event):
    user_arn = event.deep_get("userIdentity", "arn")
    return f"Suspicious AWS Secrets Manager activity detected by [{user_arn}]"


def severity(event):
    """Dynamic severity based on event type"""
    event_name = event.get("eventName")
    if event_name == "GetSecretValue":
        return "HIGH"  # Actual secret exfiltration
    elif event_name == "DescribeSecret":
        return "MEDIUM"  # Targeted reconnaissance
    else:  # ListSecrets
        return "LOW"  # General reconnaissance


def alert_context(event):
    user_arn = event.deep_get("userIdentity", "arn")
    event_name = event.get("eventName")
    return {
        "event_name": event_name,
        "threshold_used": EVENT_THRESHOLDS.get(event_name),
        "time_window_minutes": TIME_WINDOW_MINUTES,
        "activity_summary": get_activity_summary(user_arn),
        "threat_indicators": analyze_attack_progression(user_arn),
        "actor": user_arn,
        "target_account": event.deep_get("recipientAccountId"),
        "target_service": event.get("eventSource"),
    }


def get_activity_summary(user_arn):
    """Get summary of all recent activities for this user"""
    summary = {}

    for event_type in EVENT_THRESHOLDS.keys():
        cache_key = f"{RULE_ID}-{event_type.lower()}-{user_arn}"
        activities = get_string_set(cache_key)

        # Handle string response from cache (for testing)
        if isinstance(activities, str):
            import json

            try:
                activities = json.loads(activities)
            except (json.JSONDecodeError, TypeError):
                activities = set()

        count = len(activities) if activities else 0
        summary[f"{event_type.lower()}_count"] = count

    return summary


def analyze_attack_progression(user_arn):
    """Analyze if this appears to be a multi-stage attack"""
    summary = get_activity_summary(user_arn)

    indicators = []

    # Check for attack progression pattern
    if summary.get("listsecrets_count", 0) > 0:
        indicators.append("reconnaissance_phase")

    if summary.get("describesecret_count", 0) > 0:
        indicators.append("targeted_investigation")

    if summary.get("getsecretvalue_count", 0) > 0:
        indicators.append("secret_exfiltration")

    # Multi-stage attack indicator
    if len(indicators) > 1:
        indicators.append("multi_stage_attack")

    return indicators
