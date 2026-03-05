def rule(event):
    # Query already filtered for anomalies (is_anomalous = TRUE).
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("user_email"))


def title(event):
    user_email = event.get("user_email", "<UNKNOWN_USER>")
    severity_score = event.get("anomaly_severity_score", 0)

    return (
        f"Okta AD Agent Authentication Anomaly Detected: {user_email} "
        f"(Severity Score: {severity_score})"
    )


def severity(event):
    # Dynamic severity based on anomaly severity score and z-score magnitudes.
    # Higher z-scores = more standard deviations from baseline = more suspicious.
    severity_score = event.get("anomaly_severity_score", 0)
    z_volume = event.get("z_score_volume", 0)
    z_ip = event.get("z_score_ip_diversity", 0)
    z_country = event.get("z_score_country_diversity", 0)

    # Critical: Extreme anomaly (severity score > 15 or any z-score > 5)
    if severity_score > 15 or max(z_volume, z_ip, z_country) > 5:
        return "CRITICAL"

    # High: Strong anomaly (severity score > 10 or any z-score > 4)
    if severity_score > 10 or max(z_volume, z_ip, z_country) > 4:
        return "HIGH"

    # Medium: Moderate anomaly (default for detections that passed threshold)
    return "MEDIUM"


def alert_context(event):
    return {
        # User information
        "user_email": event.get("user_email", "<UNKNOWN_USER>"),
        # Baseline behavior
        "baseline_total_events": event.get("baseline_total_events", 0),
        "baseline_active_days": event.get("baseline_active_days", 0),
        "baseline_mean_events_per_hour": event.get("baseline_mean_events_per_hour", 0),
        "baseline_mean_ip_diversity": event.get("baseline_mean_ip_diversity_per_hour", 0),
        "baseline_mean_country_diversity": event.get("baseline_mean_country_diversity_per_hour", 0),
        # Recent anomalous activity
        "recent_total_events": event.get("recent_total_events", 0),
        "recent_max_events_per_hour": event.get("recent_max_events_per_hour", 0),
        "recent_max_ip_diversity": event.get("recent_max_ip_diversity_per_hour", 0),
        "recent_max_country_diversity": event.get("recent_max_country_diversity_per_hour", 0),
        "recent_max_device_diversity": event.get("recent_max_device_diversity_per_hour", 0),
        # Z-scores (standard deviations from baseline)
        "z_score_volume": event.get("z_score_volume", 0),
        "z_score_ip_diversity": event.get("z_score_ip_diversity", 0),
        "z_score_country_diversity": event.get("z_score_country_diversity", 0),
        "z_score_device_diversity": event.get("z_score_device_diversity", 0),
        "anomaly_severity_score": event.get("anomaly_severity_score", 0),
        # Geographic and network context
        "recent_ip_addresses": event.get("all_recent_ips", []),
        "recent_countries": event.get("all_recent_countries", []),
        # Temporal context
        "first_anomaly_hour": event.get("first_anomaly_hour", "<UNKNOWN>"),
        "last_anomaly_hour": event.get("last_anomaly_hour", "<UNKNOWN>"),
        "detection_timestamp": event.get("detection_timestamp", "<UNKNOWN>"),
    }


def dedup_key(event):
    # Deduplicate by user and hour to avoid alert spam during active attacks.
    user = event.get("user_email", "unknown")
    first_hour = str(event.get("first_anomaly_hour", "unknown"))

    return f"okta_ad_agent_zscore_anomaly_{user}_{first_hour}"
