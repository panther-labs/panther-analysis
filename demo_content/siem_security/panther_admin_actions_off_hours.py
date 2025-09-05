from datetime import datetime, timezone, timedelta

# Administrative actions that constitute significant system changes
ADMINISTRATIVE_ACTIONS = [
    # Detection management
    'CREATE_DETECTION', 'UPDATE_DETECTION', 'DELETE_DETECTION', 'UPDATE_DETECTION_STATE',
    'CREATE_RULE', 'UPDATE_RULE', 'DELETE_RULE', 'ENABLE_RULE', 'DISABLE_RULE',
    'CREATE_POLICY', 'UPDATE_POLICY', 'DELETE_POLICY',
    
    # User and role management 
    'CREATE_USER', 'UPDATE_USER', 'DELETE_USER', 'INVITE_USER',
    'CREATE_ROLE', 'UPDATE_ROLE', 'DELETE_ROLE', 'ASSIGN_ROLE',
    
    # System configuration
    'UPDATE_GENERAL_SETTINGS', 'UPDATE_LOG_RETENTION', 'UPDATE_ALERT_RETENTION',
    'UPDATE_SAML_SETTINGS', 'UPDATE_SSO_SETTINGS', 'GET_SAML_SETTINGS',
    
    # Log source management
    'CREATE_LOG_SOURCE', 'UPDATE_LOG_SOURCE', 'DELETE_LOG_SOURCE',
    
    # API token management
    'CREATE_API_TOKEN', 'UPDATE_API_TOKEN', 'DELETE_API_TOKEN',
    
    # Destination management
    'CREATE_DESTINATION', 'UPDATE_DESTINATION', 'DELETE_DESTINATION',
    
    # Organization and account management
    'UPDATE_ORGANIZATION', 'CREATE_ORGANIZATION', 'DELETE_ORGANIZATION'
]


def rule(event):
    """
    Detects Panther administrative actions performed during off-hours (10pm - 5am PT)
    """
    # Only process Panther audit events that succeeded
    if event.get('actionResult') != 'SUCCEEDED':
        return False
    
    # Check if this is an administrative action
    action_name = event.get('actionName', '')
    if action_name not in ADMINISTRATIVE_ACTIONS:
        return False
    
    # Get the event timestamp
    event_time_str = event.get('p_event_time')
    if not event_time_str:
        return False
    
    try:
        # Parse the UTC timestamp from the event
        if isinstance(event_time_str, str):
            event_time_utc = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        else:
            event_time_utc = event_time_str
        
        # Ensure the datetime is timezone-aware (UTC)
        if event_time_utc.tzinfo is None:
            event_time_utc = event_time_utc.replace(tzinfo=timezone.utc)
        
        # Pacific Time offset from UTC:
        # - PST (Standard Time): UTC-8 (November - March)
        # - PDT (Daylight Time): UTC-7 (March - November)
        # We'll use a simple heuristic: if month is 3-10, assume PDT (-7), else PST (-8)
        month = event_time_utc.month
        if 3 <= month <= 10:
            # Assume PDT (UTC-7) for March through October
            pacific_offset = timedelta(hours=-7)
        else:
            # Assume PST (UTC-8) for November through February
            pacific_offset = timedelta(hours=-8)
        
        pacific_tz = timezone(pacific_offset)
        event_time_pt = event_time_utc.astimezone(pacific_tz)
        
        # Extract hour in PT (24-hour format)
        hour_pt = event_time_pt.hour
        
        # Check if time is between 10pm (22:00) and 5am (05:00) PT
        # This includes: 22:00-23:59 and 00:00-04:59
        return hour_pt >= 22 or hour_pt < 5
        
    except Exception:
        # If timestamp parsing fails, don't alert
        return False


def title(event):
    """
    Generate alert title
    """
    action_name = event.get('actionName', 'Unknown Action')
    actor_email = event.deep_get('actor', 'attributes', 'email', default='Unknown User')
    
    return f"Panther admin action '{action_name}' performed during off-hours by {actor_email}"


def dedup(event):
    """
    Deduplicate by actor and action type within the time window
    """
    actor_email = event.deep_get('actor', 'attributes', 'email', default='unknown')
    action_name = event.get('actionName', 'unknown')
    
    return f"{actor_email}:{action_name}"


def alert_context(event):
    """
    Provide context for the alert
    """
    event_time_str = event.get('p_event_time', '')
    
    # Convert timestamp to PT for display
    try:
        if isinstance(event_time_str, str):
            event_time_utc = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        else:
            event_time_utc = event_time_str
            
        if event_time_utc.tzinfo is None:
            event_time_utc = event_time_utc.replace(tzinfo=timezone.utc)
        
        # Use same timezone logic as rule function
        month = event_time_utc.month
        if 3 <= month <= 10:
            pacific_offset = timedelta(hours=-7)
            tz_name = "PDT"
        else:
            pacific_offset = timedelta(hours=-8)
            tz_name = "PST"
            
        pacific_tz = timezone(pacific_offset)
        event_time_pt = event_time_utc.astimezone(pacific_tz)
        time_pt_str = event_time_pt.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')
    except Exception:
        time_pt_str = event_time_str
    
    return {
        'action_name': event.get('actionName'),
        'actor_email': event.deep_get('actor', 'attributes', 'email'),
        'actor_name': event.deep_get('actor', 'name'),
        'actor_id': event.deep_get('actor', 'id'),
        'source_ip': event.get('sourceIP'),
        'event_time_pt': time_pt_str,
        'event_time_utc': event_time_str,
        'action_result': event.get('actionResult'),
        'user_agent': event.get('userAgent')
    }


def severity(event):
    """
    Determine severity based on action type
    """
    action_name = event.get('actionName', '')
    
    # Critical actions that could disable security controls
    critical_actions = [
        'DELETE_DETECTION', 'DISABLE_RULE', 'DELETE_RULE', 'DELETE_POLICY',
        'DELETE_LOG_SOURCE', 'DELETE_DESTINATION', 'UPDATE_SAML_SETTINGS'
    ]
    
    # High-risk actions affecting users and permissions
    high_risk_actions = [
        'CREATE_USER', 'DELETE_USER', 'UPDATE_USER', 'CREATE_ROLE', 'UPDATE_ROLE', 
        'DELETE_ROLE', 'CREATE_API_TOKEN', 'UPDATE_GENERAL_SETTINGS'
    ]
    
    if action_name in critical_actions:
        return 'HIGH'
    elif action_name in high_risk_actions:
        return 'MEDIUM'
    else:
        return 'LOW'


def runbook(event):
    """
    Provide runbook for responding to off-hours admin activity
    """
    return (
        "1. Verify the legitimacy of the administrative action with the user who performed it\n"
        "2. Check if this was part of scheduled maintenance or an emergency response\n"
        "3. Review the specific action taken and assess potential security impact\n"
        "4. If unauthorized, immediately review what changes were made and consider reverting them\n"
        "5. Check for any other suspicious activity from the same user or IP address\n"
        "6. Consider implementing additional controls for off-hours administrative access"
    )
