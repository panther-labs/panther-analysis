def rule(event):
    # Query already filtered for sessions with 2+ IPs AND 2+ user agents.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user = event.get("user_email", "Unknown User")
    session_id = str(event.get("session_id", "Unknown"))[:12]
    unique_ips = event.get("unique_ips", 0)
    unique_agents = event.get("unique_agents", 0)
    return (
        f"Databricks session hijacking: session {session_id} used from "
        f"{unique_ips} IPs and {unique_agents} devices for {user}"
    )


def severity(_):
    return "HIGH"


def dedup(event):
    session_id = str(event.get("session_id", "unknown"))
    return f"session_hijack_multi_{session_id}"


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
        "is_cold_start": event.get("is_cold_start"),
        "baseline_ip_diversity": event.get("baseline_ip_diversity"),
        "baseline_agent_diversity": event.get("baseline_agent_diversity"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
    }
