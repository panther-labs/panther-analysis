def rule(event):
    """
    EC2 Compute Abuse Detection Rule

    Triggers on structured summaries from the EC2 Compute Abuse Summary Daily Query
    to identify potential cryptocurrency mining, resource abuse, and unauthorized
    high-performance computing activities.

    Returns True for any compute usage patterns that indicate potential abuse.
    """
    # Extract key indicators from the event
    gpu_instances = event.get("gpu_instances", 0)
    max_risk_score = event.get("max_risk_score", 0)
    total_instances = event.get("total_instances_requested", 0)
    abuse_indicators = event.get("abuse_indicators", [])

    # Critical: Any GPU instance usage (potential crypto mining)
    if gpu_instances > 0:
        return True

    # High risk: Very expensive instance types or bulk launches
    if max_risk_score >= 8.0 or total_instances > 50:
        return True

    # Medium risk: Multiple abuse indicators or significant compute usage
    if len(abuse_indicators) >= 2 or total_instances > 20:
        return True

    # High-risk score threshold
    if max_risk_score >= 5.0:
        return True

    # Normal activity - no alert
    return False


def title(event):
    """Generate dynamic alert title based on compute abuse patterns"""
    actor_name = event.get("actor_name", "Unknown Actor")
    abuse_indicators = event.get("abuse_indicators", [])
    gpu_instances = event.get("gpu_instances", 0)
    total_instances = event.get("total_instances_requested", 0)

    # Prioritize GPU usage (crypto mining indicator)
    if gpu_instances > 0:
        return (
            f"Potential Cryptocurrency Mining: {actor_name} launched {gpu_instances} GPU instances"
        )

    # High-risk indicators
    if "bulk_instance_creation" in abuse_indicators:
        return f"Bulk EC2 Instance Creation: {actor_name} requested {total_instances} instances"

    if "high_risk_instance_types" in abuse_indicators:
        return f"High-Risk Compute Usage: {actor_name} using expensive instance types"

    if "multi_region_deployment" in abuse_indicators:
        return f"Multi-Region Compute Deployment: {actor_name} across multiple regions"

    # General compute abuse
    return f"Suspicious EC2 Compute Activity: {actor_name} ({len(abuse_indicators)} indicators)"


def alert_context(event):
    """Provide detailed context for security investigation"""
    return {
        "actor_details": {
            "actor_arn": event.get("actor_arn"),
            "actor_name": event.get("actor_name"),
            "source_ips": event.get("source_ips", []),
            "unique_ips": event.get("unique_ips", 0),
            "regions_used": event.get("regions_used", []),
            "unique_regions": event.get("unique_regions", 0),
        },
        "compute_activity": {
            "instances_launched": event.get("instances_launched", 0),
            "instances_terminated": event.get("instances_terminated", 0),
            "total_instances_requested": event.get("total_instances_requested", 0),
            "instance_types_used": event.get("instance_types_used", []),
            "amis_used": event.get("amis_used", []),
        },
        "resource_classification": {
            "gpu_instances": event.get("gpu_instances", 0),
            "high_performance_instances": event.get("high_performance_instances", 0),
            "memory_optimized_instances": event.get("memory_optimized_instances", 0),
        },
        "risk_assessment": {
            "max_risk_score": event.get("max_risk_score", 0),
            "total_risk_score": event.get("total_risk_score", 0),
            "abuse_indicators": event.get("abuse_indicators", []),
        },
        "timeline": {
            "time_window": event.get("time_window"),
            "first_activity": event.get("first_activity"),
            "last_activity": event.get("last_activity"),
        },
        "investigation_guidance": {
            "priority": "CRITICAL" if event.get("gpu_instances", 0) > 0 else "HIGH",
            "next_steps": [
                "Review CloudTrail logs for the actor during the time window",
                "Check instance usage patterns and resource consumption",
                "Investigate source IP addresses for external access",
                "Verify business justification for high-performance compute usage",
                "Check for crypto mining indicators (network traffic, CPU patterns)",
            ],
        },
    }


def severity(event):
    """Dynamic severity based on abuse patterns and risk score"""
    gpu_instances = event.get("gpu_instances", 0)
    max_risk_score = event.get("max_risk_score", 0)
    total_instances = event.get("total_instances_requested", 0)
    abuse_indicators = event.get("abuse_indicators", [])

    # Critical: GPU instances (crypto mining)
    if gpu_instances > 0:
        return "CRITICAL"

    # High: Very risky instance types or bulk launches
    if max_risk_score >= 8.0 or total_instances > 50:
        return "HIGH"

    # Medium: Multiple abuse indicators or significant compute usage
    if len(abuse_indicators) >= 3 or total_instances > 20:
        return "MEDIUM"

    # Default for other suspicious patterns
    return "LOW"
