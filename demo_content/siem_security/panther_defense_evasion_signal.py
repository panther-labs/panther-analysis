def rule(event):
    """
    Signal for critical Panther administrative actions that could indicate defense evasion,
    insider threats, or unauthorized tampering with security controls.
    """
    # Must be a successful action to indicate actual impact
    if event.get("actionResult") != "SUCCEEDED":
        return False
    
    action_name = event.get("actionName")
    
    # Special handling for detection state updates - only alert on disabling
    if action_name == "UPDATE_DETECTION_STATE":
        detections = event.deep_get("actionParams", "dynamic", "input", "detections", default=[])
        
        # Only alert if any detections are being disabled
        for detection in detections:
            if detection.get("enabled") is False:
                return True
        return False
    
    # High-risk actions that could indicate defense evasion
    critical_actions = {
        # Detection tampering
        "DELETE_DETECTION",
        "DELETE_RULE_V2",
        
        # Log source tampering
        "DELETE_LOG_SOURCE",
        "UPDATE_LOG_SOURCE",
        "UPDATE_LOG_SOURCE_FILTERS",
        
        # Alert routing tampering
        "DELETE_ALERT_DESTINATION",
        "UPDATE_ALERT_DESTINATION",
        
        # User and access control tampering
        "DELETE_USER",
        "CREATE_USER_ROLE",
        "DELETE_USER_ROLE", 
        "DELETE_API_TOKEN",
        
        # System configuration tampering
        "UPDATE_SAML_SETTINGS",
        "UPDATE_GENERAL_SETTINGS",
        "DELETE_CLOUD_ACCOUNT",
        
        # Data enrichment tampering
        "DELETE_LOOKUP_TABLE",
        "DELETE_ENRICHMENT",
        
        # Bulk operations (potentially suspicious)
        "BULK_DELETE_DETECTIONS",
        "BULK_UPDATE_DETECTIONS"
    }
    
    return action_name in critical_actions


def alert_context(event):
    """Provide detailed context for investigation"""
    return {
        "action": event.get("actionName"),
        "actor": event.get("actor", {}),
        "source_ip": event.get("sourceIP"),
        "timestamp": event.get("timestamp"),
        "user_agent": event.get("userAgent"),
        "result": event.get("actionResult"),
        "action_params": event.get("actionParams", {})
    }