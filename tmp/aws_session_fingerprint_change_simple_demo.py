"""
Simple session fingerprint detection that tracks user agent changes within the same session.
This version uses in-memory storage for demonstration and testing purposes.
"""

# In-memory cache for demo purposes
_session_cache = {}

def rule(event):
    """
    Detects when the same AWS session uses different User-Agent signatures,
    indicating potential stolen session credentials or session hijacking.
    """
    # Skip service accounts and internal AWS calls
    if not is_human_or_application_session(event):
        return False

    session_id = get_session_identifier(event)
    if not session_id:
        return False

    # Create fingerprint from User Agent (IP can change legitimately)
    ua = event.get("userAgent", "")
    fingerprint = normalize_user_agent(ua)

    # Check if we've seen this session before
    if session_id not in _session_cache:
        _session_cache[session_id] = {fingerprint}
        return False

    # Alert if we see a different fingerprint for existing session
    cached_fingerprints = _session_cache[session_id]
    if fingerprint not in cached_fingerprints:
        cached_fingerprints.add(fingerprint)
        return True

    return False


def normalize_user_agent(ua):
    """
    Normalize user agent to detect major changes while ignoring minor variations.
    Focus on distinguishing between human (browser) vs automation (CLI/SDK).
    """
    if not ua:
        return "unknown"
    
    ua_lower = ua.lower()
    
    # Browser patterns
    if any(browser in ua_lower for browser in ['mozilla', 'chrome', 'safari', 'firefox', 'edge']):
        return "browser"
    
    # AWS CLI patterns
    if 'aws-cli' in ua_lower:
        return "aws-cli"
    
    # SDK patterns
    if any(sdk in ua_lower for sdk in ['boto3', 'aws-sdk', 'python-urllib3']):
        return "aws-sdk"
    
    # Console/service patterns
    if 'console.aws.amazon.com' in ua_lower:
        return "aws-console-backend"
        
    # AWS services
    if any(service in ua_lower for service in ['lambda.amazonaws.com', 'ecs.amazonaws.com']):
        return "aws-service"
    
    # Default to the first 50 characters for unknown user agents
    return ua[:50]


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
    ua = normalize_user_agent(event.get("userAgent", ""))
    return f"AWS session fingerprint change detected for [{user_arn}] - new tool signature [{ua}]"


def alert_context(event):
    """Provide investigation context"""
    session_id = get_session_identifier(event)
    ua = event.get("userAgent", "")
    
    # Get cached fingerprints
    cached_fingerprints = _session_cache.get(session_id, set())
    
    return {
        "user_arn": event.deep_get("userIdentity", "arn", default=""),
        "session_identifier": session_id,
        "current_user_agent": ua,
        "current_fingerprint": normalize_user_agent(ua),
        "previous_fingerprints": list(cached_fingerprints),
        "event_name": event.get("eventName", ""),
        "event_time": event.get("eventTime", ""),
        "aws_region": event.get("awsRegion", ""),
        "source_ip_address": event.get("sourceIPAddress", ""),
    }


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