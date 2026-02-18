def rule(_):
    # Query already filtered for statistical anomalies
    return True


def title(event):
    actor = event.get("actorId", "<UNKNOWN_ACTOR>")
    access_count = event.get("N", 0)
    zscore = event.get("p_zscore", 0)

    return f"Okta SWA Bulk Access: {actor} accessed {access_count} apps (z-score: {zscore:.2f})"


def severity(event):
    zscore = event.get("p_zscore", 0)
    access_count = event.get("N", 0)

    # Extremely high z-score or very high access count is critical
    if zscore >= 5 or access_count >= 20:
        return "CRITICAL"

    # High z-score is high severity
    if zscore >= 4 or access_count >= 10:
        return "HIGH"

    # Medium z-score (threshold is 3 in the query)
    if zscore >= 3:
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    access_count = event.get("N", 0)
    mean = event.get("p_mean", 0)

    return {
        "actor_id": event.get("actorId", "<UNKNOWN_ACTORID>"),
        "access_count": access_count,
        "historical_mean": mean,
        "standard_deviation": event.get("p_stddev", 0),
        "z_score": event.get("p_zscore", 0),
        "time_window_start": event.get("t1", "<UNKNOWN_TIMEWINDOWSTART>"),
        "time_window_end": event.get("t2", "<UNKNOWN_TIMEWINDOWEND>"),
        "anomaly_description": (
            f"User accessed {access_count} SWA apps " f"vs historical average of {mean:.1f}"
        ),
    }
