def rule(event):
    # Query already filtered for scanning pattern (3+ IPs, low events/IP).
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user = event.get("user_email", "Unknown User")
    token_id = event.get("token_id", "Unknown")
    unique_ips = event.get("unique_ips", 0)
    events_per_ip = event.get("events_per_ip", 0)
    failure_rate = event.get("failure_rate_pct", 0)
    return (
        f"Token scanning detected: token {token_id} for {user} used from "
        f"{unique_ips} IPs ({events_per_ip} events/IP, {failure_rate}% failures)"
    )


def severity(event):
    score = event.get("anomaly_severity_score") or 0
    failure_rate = event.get("failure_rate_pct") or 0

    if failure_rate > 50 or score > 30:
        return "HIGH"
    if score > 10:
        return "MEDIUM"
    return "LOW"


def dedup(event):
    token_id = event.get("token_id", "unknown")
    return f"token_scanning_{token_id}"


def alert_context(event):
    return {
        "user_email": event.get("user_email"),
        "token_id": event.get("token_id"),
        "total_events": event.get("total_events"),
        "unique_ips": event.get("unique_ips"),
        "unique_agents": event.get("unique_agents"),
        "events_per_ip": event.get("events_per_ip"),
        "failed_events": event.get("failed_events"),
        "failure_rate_pct": event.get("failure_rate_pct"),
        "ip_list": event.get("ip_list"),
        "first_event": str(event.get("first_event")),
        "last_event": str(event.get("last_event")),
        "z_score_token_ips": event.get("z_score_token_ips"),
        "is_cold_start": event.get("is_cold_start"),
        "baseline_ip_diversity": event.get("baseline_ip_diversity"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
    }
