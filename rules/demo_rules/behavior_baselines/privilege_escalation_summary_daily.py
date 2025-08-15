def rule(event):
    """
    Triggers when privilege escalation activity summary data is generated.
    This rule is triggered by scheduled queries that generate structured summaries.
    """
    return True


def title(event):
    return "Privilege Escalation Activity Summary Generated"


def alert_context(event):
    return {
        "summary_type": "privilege_escalation",
        "period": "24_hours",
        "structured_data_available": True,
        "data_sources": ["AWS.CloudTrail"],
        "investigation_patterns": [
            "iam_policy_analysis",
            "role_assumption_tracking",
            "admin_activity_monitoring",
            "permission_boundary_analysis",
            "service_account_monitoring",
        ],
    }
