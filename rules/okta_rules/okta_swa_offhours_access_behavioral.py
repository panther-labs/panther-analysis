def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("admin_email"))


def title(event):
    admin = event.get("admin_email", "Unknown")
    is_geo_shift = event.get("is_geographic_shift") or False
    recent_late_night = event.get("recent_total_late_night") or 0
    baseline_country = event.get("baseline_primary_country", "Unknown")
    recent_country = event.get("recent_primary_country", "Unknown")
    if is_geo_shift and recent_late_night > 0:
        return (
            f"Okta SWA: Late-Night Credential Access with Geographic Shift for {admin}"
            f" ({baseline_country} -> {recent_country})"
        )
    if recent_late_night > 0:
        return f"Okta SWA: Off-Hours Late-Night Credential Access by {admin}"
    if is_geo_shift:
        return (
            f"Okta SWA: Off-Hours Credential Access with Geographic Shift for {admin}"
            f" ({baseline_country} -> {recent_country})"
        )
    return f"Okta SWA: Off-Hours Credential Access Anomaly for {admin}"


def severity(event):
    is_geo_shift = event.get("is_geographic_shift") or False
    recent_late_night = event.get("recent_total_late_night") or 0
    is_first_late_night = event.get("is_first_time_late_night") or False
    is_late_night_anomaly = event.get("is_late_night_ratio_anomaly") or False
    is_offhours_anomaly = event.get("is_offhours_ratio_anomaly") or False
    score = event.get("anomaly_severity_score") or 0
    if is_geo_shift and recent_late_night > 0:
        return "CRITICAL"
    is_temporal_anomaly = is_late_night_anomaly or is_offhours_anomaly
    if (
        recent_late_night > 0
        or is_geo_shift
        or is_first_late_night
        or is_temporal_anomaly
        or score > 20
    ):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return {
        "admin_email": event.get("admin_email"),
        "recent_total_late_night": event.get("recent_total_late_night"),
        "recent_total_offhours": event.get("recent_total_offhours"),
        "recent_total_weekend": event.get("recent_total_weekend"),
        "recent_late_night_ratio": event.get("recent_late_night_ratio"),
        "recent_offhours_ratio": event.get("recent_offhours_ratio"),
        "baseline_late_night_ratio": event.get("baseline_late_night_ratio"),
        "baseline_offhours_ratio": event.get("baseline_offhours_ratio"),
        "z_score_late_night_ratio": event.get("z_score_late_night_ratio"),
        "z_score_offhours_ratio": event.get("z_score_offhours_ratio"),
        "is_geographic_shift": event.get("is_geographic_shift"),
        "baseline_primary_country": event.get("baseline_primary_country"),
        "recent_primary_country": event.get("recent_primary_country"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
        "recent_first_event": event.get("recent_first_event"),
        "recent_last_event": event.get("recent_last_event"),
    }
