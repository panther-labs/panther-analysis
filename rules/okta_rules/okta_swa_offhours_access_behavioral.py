def rule(_):
    # Query already filtered for statistical anomalies
    return True


def title(event):
    user_hour_key = event.get("user_hour_key", "<UNKNOWN>")
    parts = user_hour_key.split("|")
    actor = parts[0] if len(parts) > 0 else "<UNKNOWN_ACTOR>"
    hour = parts[1] if len(parts) > 1 else "<UNKNOWN_HOUR>"

    access_count = event.get("N", 0)
    zscore = event.get("p_zscore", 0)

    return (
        f"Okta SWA Unusual Time Access: {actor} at hour {hour} UTC "
        f"({access_count} accesses, z-score: {zscore:.2f})"
    )


def severity(event):
    # Pure behavioral severity based on z-score (how anomalous the behavior is)
    # This aligns with the behavioral detection approach and doesn't rely on hardcoded hours
    zscore = event.get("p_zscore", 0)

    # Extremely anomalous behavior (>5 std deviations)
    if zscore >= 5:
        return "HIGH"

    # Highly anomalous behavior (>3 std deviations)
    if zscore >= 3:
        return "MEDIUM"

    # Moderately anomalous (query threshold is 2)
    if zscore >= 2:
        return "LOW"

    return "DEFAULT"


def alert_context(event):
    user_hour_key = event.get("user_hour_key", "<UNKNOWN_USERHOURKEY>")
    parts = user_hour_key.split("|")
    actor = parts[0] if len(parts) > 0 else "<UNKNOWN_ACTORID>"
    hour = parts[1] if len(parts) > 1 else "<UNKNOWN_HOUR>"

    return {
        "actor_id": actor,
        "hour_of_day_utc": hour,
        "access_count": event.get("N", 0),
        "historical_mean_for_hour": event.get("p_mean", 0),
        "standard_deviation": event.get("p_stddev", 0),
        "z_score": event.get("p_zscore", 0),
        "time_window_start": event.get("t1", "<UNKNOWN_TIMEWINDOWSTART>"),
        "time_window_end": event.get("t2", "<UNKNOWN_TIMEWINDOWEND>"),
        "anomaly_description": (
            f"User accessed SWA apps {event.get('N', 0)} times at hour {hour} UTC "
            f"vs historical average of {event.get('p_mean', 0):.1f}"
        ),
    }
