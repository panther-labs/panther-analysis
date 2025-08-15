def rule(event):
    """
    Triggers when user authentication summary data is generated.
    This rule is triggered by scheduled queries that generate structured summaries.
    """
    return True


def title(event):
    return "User Authentication Summary Generated"


def alert_context(event):
    return {
        "summary_type": "user_authentication",
        "period": "1_hour",
        "structured_data_available": True,
        "agent_consumption_ready": True,
        "investigation_patterns": [
            "failed_logins_analysis",
            "location_anomaly_detection",
            "mfa_compliance_tracking",
            "credential_stuffing_detection",
        ],
    }
