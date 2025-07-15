from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "AWS.CrossRegion.Activity"
UNIQUE_REGION_THRESHOLD = 3
WITHIN_TIMEFRAME_MINUTES = 10


def rule(event):
    # Only process CloudTrail events with a user
    user = event.udm("actor_user")
    if not user:
        return False
    region = event.get("awsRegion")
    if not region:
        return False
    key = f"{RULE_ID}-{user}"
    unique_regions = add_to_string_set(key, region, WITHIN_TIMEFRAME_MINUTES * 60)
    try:
        import json
        if isinstance(unique_regions, str):
            unique_regions = json.loads(unique_regions)
    except Exception:
        pass
    return len(unique_regions) >= UNIQUE_REGION_THRESHOLD


def title(event):
    user = event.udm("actor_user") or "unknown user"
    return f"Simultaneous activity across multiple AWS regions for [{user}]"


def alert_context(event):
    return {
        "actor": event.udm("actor_user") or "",
        "region": event.get("awsRegion", ""),
        "event_name": event.get("eventName", ""),
        "source_ip": event.get("sourceIPAddress", ""),
        "user_agent": event.get("userAgent", ""),
        "timestamp": event.get("eventTime", ""),
    }


def runbook(event):
    user = event.udm("actor_user") or "unknown user"
    return f"""
1. Review CloudTrail activity for [{user}] across all regions in the last 10 minutes.
2. Confirm if the activity was expected or authorized (e.g., automation, multi-region deployment).
3. Investigate for signs of credential compromise or automated attack.
4. If suspicious, rotate credentials and review user permissions.
""" 