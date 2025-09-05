def rule(event):
    """
    Medium severity alert for suspicious changes to alert destination severity routing.
    Detects when high or critical severities are removed from destinations or when
    alert destinations are configured to only receive low-priority alerts.
    """
    # Must be a successful alert destination update
    if (event.get("actionResult") != "SUCCEEDED" or 
        event.get("actionName") != "UPDATE_ALERT_DESTINATION"):
        return False
    
    # Check for suspicious severity routing changes
    default_for_severity = event.deep_get("actionParams", "dynamic", "input", "defaultForSeverity", default=[])
    
    # Alert if destination is set to only handle INFO or LOW severity
    # This could indicate an attempt to hide critical alerts
    if default_for_severity and all(sev in ["INFO", "LOW"] for sev in default_for_severity):
        return True
    
    return False


def title(event):
    """Generate alert title with actor and destination info"""
    actor_name = event.deep_get("actor", "name", default="Unknown")
    destination_name = event.deep_get("actionParams", "dynamic", "input", "displayName", default="Unknown Destination")
    
    return f"Alert destination severity routing changed by {actor_name} for {destination_name}"


def alert_context(event):
    """Provide detailed context for investigation"""
    return {
        "action": event.get("actionName"),
        "actor": event.get("actor", {}),
        "source_ip": event.get("sourceIP"),
        "timestamp": event.get("timestamp"),
        "user_agent": event.get("userAgent"),
        "destination_name": event.deep_get("actionParams", "dynamic", "input", "displayName"),
        "destination_type": event.deep_get("actionParams", "dynamic", "input", "outputType"),
        "alert_types": event.deep_get("actionParams", "dynamic", "input", "alertTypes", default=[]),
        "default_for_severity": event.deep_get("actionParams", "dynamic", "input", "defaultForSeverity", default=[]),
        "log_types": event.deep_get("actionParams", "dynamic", "input", "logTypes", default=[]),
        "output_config": event.deep_get("actionParams", "dynamic", "input", "outputConfig", default={}),
        "investigation_steps": [
            "Verify if this change was authorized and documented",
            "Check if other alert destinations are properly configured for high/critical alerts",
            "Review recent administrative activity by this user",
            "Confirm alert routing is working as expected for critical security events"
        ]
    }