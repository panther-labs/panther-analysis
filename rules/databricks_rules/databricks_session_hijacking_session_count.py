def rule(event):
    # Query already filtered for is_anomalous = TRUE (3+ distinct public IPs per session).
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user = event.get("user_email", "Unknown User")
    session_id = str(event.get("session_id", "Unknown"))[:12]
    unique_ips = event.get("unique_ips", 0)
    return (
        f"Databricks session hijacking: session {session_id} used from "
        f"{unique_ips} distinct public IPs for {user}"
    )


def severity(event):
    score = event.get("anomaly_severity_score") or 0
    if score > 50:
        return "CRITICAL"
    if score > 30:
        return "HIGH"
    return "MEDIUM"


def dedup(event):
    session_id = str(event.get("session_id", "unknown"))
    return f"session_hijack_count_{session_id}"


def alert_context(event):
    return {
        "user_email": event.get("user_email"),
        "session_id": event.get("session_id"),
        "unique_ips": event.get("unique_ips"),
        "unique_agents": event.get("unique_agents"),
        "ip_list": event.get("ip_list"),
        "agent_list": event.get("agent_list"),
        "first_event": str(event.get("first_event")),
        "last_event": str(event.get("last_event")),
        "z_score_session_ips": event.get("z_score_session_ips"),
        "is_cold_start": event.get("is_cold_start"),
        "baseline_mean_ips_per_day": event.get("baseline_mean_ips_per_day"),
        "baseline_active_days": event.get("baseline_active_days"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
    }
