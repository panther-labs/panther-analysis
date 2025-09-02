def rule(event):
    """
    Panther Administrative Actions Baseline Summary
    
    Always triggers to generate structured summaries of administrative activities
    for AI consumption and behavioral analysis. Provides pre-processed administrative
    intelligence for SIEM compromise detection and privilege escalation monitoring.
    
    Returns True for all events to maintain visibility into administrative patterns.
    """
    return True


def title(event):
    """Generate summary title for administrative actions baseline"""  
    return "Administrative Actions Baseline Summary Generated"


def alert_context(event):
    """Provide structured data for AI consumption and behavioral analysis"""
    return {
        "summary_type": "administrative_patterns",
        "period": "24_hours",
        "structured_data_available": True, 
        "agent_consumption_ready": True,
        "data_sources": ["Panther.Audit"],
        "investigation_patterns": [
            "siem_compromise_detection",
            "privilege_escalation_analysis",
            "alert_destination_monitoring", 
            "user_management_tracking",
            "api_token_activity_analysis",
            "lateral_movement_detection"
        ]
    }