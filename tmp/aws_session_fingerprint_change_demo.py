import json
from panther_detection_helpers.caching import add_to_string_set, get_string_set

RULE_ID = "AWS.Session.Fingerprint.Change"


def rule(event):
    """
    Detects when the same AWS session uses different IP/User-Agent combinations,
    indicating potential stolen session credentials or session hijacking.
    """
    # Skip service accounts and internal AWS calls
    if not is_human_or_application_session(event):
        return False

    session_id = get_session_identifier(event)
    if not session_id:
        return False

    # Create fingerprint from IP and User Agent
    ip = event.get("sourceIPAddress", "")
    ua = event.get("userAgent", "")
    fingerprint = f"{ip}:{ua}"

    # Check cached fingerprints for this session (8 hour TTL in seconds)
    cache_key = f"session-fingerprints-{session_id}"
    ttl_seconds = 8 * 60 * 60  # 8 hours
    
    # Add current fingerprint to cache and get all fingerprints for this session
    cached_fingerprints = add_to_string_set(cache_key, fingerprint, ttl_seconds)
    
    # Handle cache response format (can be string or list)
    if isinstance(cached_fingerprints, str):
        try:
            cached_fingerprints = json.loads(cached_fingerprints)
        except (json.JSONDecodeError, TypeError):
            cached_fingerprints = [cached_fingerprints]
    
    if not isinstance(cached_fingerprints, list):
        cached_fingerprints = [cached_fingerprints]
    
    # Alert if we see more than one unique fingerprint for this session
    unique_fingerprints = set(cached_fingerprints)
    return len(unique_fingerprints) > 1


def get_session_identifier(event):
    """Extract unique session identifier from CloudTrail event"""
    user_type = event.deep_get("userIdentity", "type")

    if user_type == "AssumedRole":
        # Use full assumed role ARN (includes unique session name)
        return event.deep_get("userIdentity", "arn")
    elif user_type == "IAMUser":
        # For IAM users, use access key if available
        access_key = event.deep_get("userIdentity", "accessKeyId")
        if access_key:
            return access_key

    # Fallback to user ARN
    return event.deep_get("userIdentity", "arn")


def is_human_or_application_session(event):
    """Filter out service accounts and AWS internal calls"""
    source_ip = event.get("sourceIPAddress", "")
    user_agent = event.get("userAgent", "")

    # Skip AWS service calls
    aws_services = [
        "lambda.amazonaws.com",
        "ecs.amazonaws.com",
        "states.amazonaws.com",
        "events.amazonaws.com",
        "monitoring.amazonaws.com",
    ]
    if source_ip in aws_services:
        return False

    # Skip if no meaningful user agent
    if not user_agent or user_agent == "unknown":
        return False

    # Skip AWS internal service user agents
    if "amazon-kinesis-client-library" in user_agent:
        return False

    return True


def title(event):
    """Generate dynamic alert title"""
    user_arn = event.deep_get("userIdentity", "arn", default="unknown user")
    ip = event.get("sourceIPAddress", "unknown IP")
    return f"AWS session fingerprint change detected for [{user_arn}] from IP [{ip}]"


def alert_context(event):
    """Provide investigation context"""
    session_id = get_session_identifier(event)
    ip = event.get("sourceIPAddress", "")
    ua = event.get("userAgent", "")
    
    # Get cached fingerprints to show the change
    cache_key = f"session-fingerprints-{session_id}"
    cached_fingerprints = get_string_set(cache_key) or []
    
    # Handle cache response format
    if isinstance(cached_fingerprints, str):
        try:
            cached_fingerprints = json.loads(cached_fingerprints)
        except (json.JSONDecodeError, TypeError):
            cached_fingerprints = [cached_fingerprints]
    
    return {
        "user_arn": event.deep_get("userIdentity", "arn", default=""),
        "session_identifier": session_id,
        "current_ip": ip,
        "current_user_agent": ua,
        "current_fingerprint": f"{ip}:{ua}",
        "previous_fingerprints": list(cached_fingerprints),
        "event_name": event.get("eventName", ""),
        "event_time": event.get("eventTime", ""),
        "aws_region": event.get("awsRegion", ""),
        "source_ip_address": ip,
    }


def runbook(event):
    """Investigation runbook"""
    user_arn = event.deep_get("userIdentity", "arn", default="unknown user")
    return f"""
## Session Fingerprint Change - {user_arn}

### Immediate Actions:
1. Contact user to confirm legitimate tool switching
2. Review CloudTrail activity 30 minutes before/after this event
3. Look for privilege escalation or data access patterns

### Investigation:
- Check user agent change (browser ↔ CLI)
- Verify if IP address changed unexpectedly  
- Look for rapid API calls after fingerprint change
- Check access to sensitive resources (IAM, Secrets, S3)

### Response:
- If suspicious: Rotate credentials immediately
- If confirmed breach: Revoke session, audit activity
- Consider temporary permission restrictions

### Common False Positives:
- Legitimate Console ↔ CLI switching
- Browser updates, network changes
"""


def severity(event):
    """Dynamic severity based on user type and operations"""
    user_arn = event.deep_get("userIdentity", "arn", default="")
    event_name = event.get("eventName", "")
    
    # Higher severity for admin users or sensitive operations
    if "Admin" in user_arn or "Root" in user_arn:
        return "High"
    
    # Higher severity for sensitive operations
    sensitive_operations = [
        "CreateAccessKey", "CreateUser", "AttachUserPolicy", 
        "CreateSecret", "GetSecretValue", "PutBucketPolicy"
    ]
    if event_name in sensitive_operations:
        return "High"
    
    return "Medium"