def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user = event.get("user_email", "Unknown User")
    recent = event.get("recent_admin_queries", 0)
    baseline_mean = event.get("baseline_mean_per_day", 0)
    is_cold_start = event.get("is_cold_start") or False

    if is_cold_start:
        return f"Spike in admin activity: {user} ran {recent} admin queries (no prior baseline)"
    ratio = event.get("ratio_vs_baseline")
    if ratio:
        return (
            f"Spike in admin activity: {user} ran {recent} admin queries"
            f" ({ratio}x baseline avg of {baseline_mean})"
        )
    return f"Spike in admin activity: {user} ran {recent} admin queries"


def severity(event):
    score = event.get("anomaly_severity_score") or 0
    is_cold_start = event.get("is_cold_start") or False
    recent = event.get("recent_admin_queries") or 0

    if score > 50 or (is_cold_start and recent > 20):
        return "HIGH"
    if score > 20:
        return "MEDIUM"
    return "LOW"


def dedup(event):
    user = event.get("user_email", "unknown")
    return f"spike_admin_activity_{user}"


def alert_context(event):
    return {
        "user_email": event.get("user_email"),
        "recent_admin_queries": event.get("recent_admin_queries"),
        "recent_unique_actions": event.get("recent_unique_actions"),
        "recent_unique_workspaces": event.get("recent_unique_workspaces"),
        "action_list": event.get("action_list"),
        "first_event": str(event.get("first_event")),
        "last_event": str(event.get("last_event")),
        "baseline_active_days": event.get("baseline_active_days"),
        "baseline_mean_per_day": event.get("baseline_mean_per_day"),
        "baseline_stddev_per_day": event.get("baseline_stddev_per_day"),
        "baseline_max_per_day": event.get("baseline_max_per_day"),
        "z_score_admin_queries": event.get("z_score_admin_queries"),
        "ratio_vs_baseline": event.get("ratio_vs_baseline"),
        "is_cold_start": event.get("is_cold_start"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
    }
