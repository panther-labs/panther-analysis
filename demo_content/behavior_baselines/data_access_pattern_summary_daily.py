def rule(event):
    """
    Triggers when data access pattern summary data is generated.
    This rule is triggered by scheduled queries that generate structured summaries.
    """
    return True


def title(event):
    return "Data Access Pattern Summary Generated"


def alert_context(event):
    return {
        "summary_type": "data_access_patterns",
        "period": "24_hours",
        "structured_data_available": True,
        "data_sources": ["AWS.CloudTrail", "AWS.S3ServerAccess"],
        "investigation_patterns": [
            "data_exfiltration_monitoring",
            "insider_threat_detection",
            "sensitive_data_tracking",
            "bulk_access_analysis",
            "cross_account_activity_monitoring",
        ],
    }
