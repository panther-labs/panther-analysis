def rule(event):
    """
    Detects when multiple detections are disabled in a short period, 
    which may indicate malicious insider activity or defense evasion.
    """
    # Must be an UPDATE_DETECTION_STATE action that succeeded
    if event.get("actionName") != "UPDATE_DETECTION_STATE":
        return False
    
    if event.get("actionResult") != "SUCCEEDED":
        return False
    
    # Check if any detections were disabled in this action
    detections = event.deep_get("actionParams", "dynamic", "input", "detections", default=[])
    
    # Count how many detections were disabled (enabled: false)
    disabled_count = sum(1 for detection in detections if not detection.get("enabled", True))
    
    # Only trigger if at least one detection was disabled
    # The aggregation rule will handle counting multiple events
    return disabled_count > 0


def title(event):
    """Generate dynamic alert title with count of disabled detections"""
    actor_name = event.deep_get("actor", "name", default="Unknown User")    
    return f"{actor_name} disabled a group of detections"


def alert_context(event):
    """Provide context about which detections were disabled"""
    detections = event.deep_get("actionParams", "dynamic", "input", "detections", default=[])
    
    disabled_detections = [
        detection.get("id") for detection in detections 
        if not detection.get("enabled", True)
    ]
    
    return {
        "actor": event.get("actor", {}),
        "disabled_detections": disabled_detections,
        "disabled_count": len(disabled_detections),
        "total_detections_in_request": len(detections),
        "source_ip": event.get("sourceIP"),
        "user_agent": event.get("userAgent"),
        "timestamp": event.get("timestamp")
    }
