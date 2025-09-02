def rule(event):
    """
    Detects when log sources are deleted in Panther SIEM platform.
    
    Log source deletion can indicate:
    - Defense evasion attempts to reduce security visibility
    - Administrative cleanup activities (legitimate)
    - Accidental misconfiguration
    - Evidence destruction attempts
    
    This low-severity rule provides broader coverage for tracking log source
    management activities while avoiding alert fatigue.
    """
    return (
        event.get("actionName") == "DELETE_LOG_SOURCE" 
        and event.get("actionResult") == "SUCCEEDED"
    )


def title(event):
    """Generate dynamic alert title with actor and timing information."""
    actor_name = event.deep_get("actor", "name", default="Unknown User")
    source_ip = event.get("sourceIP", "Unknown IP")
    
    return f"Log Source Deleted by {actor_name} from {source_ip}"


def alert_context(event):
    """Provide comprehensive context for investigation."""
    context = {
        "actor_id": event.deep_get("actor", "id"),
        "actor_name": event.deep_get("actor", "name"),
        "actor_email": event.deep_get("actor", "attributes", "email"),
        "actor_role": event.deep_get("actor", "attributes", "roleName"),
        "source_ip": event.get("sourceIP"),
        "user_agent": event.get("userAgent"),
        "action_name": event.get("actionName"),
        "action_result": event.get("actionResult"),
        "timestamp": event.get("timestamp"),
        "panther_version": event.get("pantherVersion")
    }
    
    # Extract log source details if available
    action_params = event.deep_get("actionParams", "dynamic", "input")
    if action_params:
        context.update({
            "log_source_id": action_params.get("logSourceId"),
            "log_source_name": action_params.get("name"),
            "integration_type": action_params.get("integrationType"),
            "log_types": action_params.get("logTypes", [])
        })
    
    return context