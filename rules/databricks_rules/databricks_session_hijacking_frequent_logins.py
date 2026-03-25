def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user = event.get("user_email", "Unknown User")
    unique_ips = event.get("hourly_unique_ips", 0)
    unique_agents = event.get("hourly_unique_agents", 0)
    return (
        f"Databricks session hijacking: {user} logged in from "
        f"{unique_ips} IPs and {unique_agents} devices in one hour"
    )


def severity(event):
    score = event.get("anomaly_severity_score") or 0
    is_cold_start = event.get("is_cold_start") or False
    if is_cold_start and score > 10:
        return "HIGH"
    if score > 20:
        return "HIGH"
    return "MEDIUM"


def dedup(event):
    user = event.get("user_email", "unknown")
    hour = str(event.get("event_hour", "unknown"))[:13]
    return f"session_hijack_freq_{user}_{hour}"


def alert_context(event):
    return {
        "user_email": event.get("user_email"),
        "event_hour": str(event.get("event_hour")),
        "hourly_unique_ips": event.get("hourly_unique_ips"),
        "hourly_unique_agents": event.get("hourly_unique_agents"),
        "ip_list": event.get("ip_list"),
        "agent_list": event.get("agent_list"),
        "z_score_unique_ips": event.get("z_score_unique_ips"),
        "is_cold_start": event.get("is_cold_start"),
        "baseline_mean_ips_per_day": event.get("baseline_mean_ips_per_day"),
        "baseline_active_days": event.get("baseline_active_days"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
    }
