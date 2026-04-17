def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("admin_email"))


def title(event):
    admin = event.get("admin_email", "Unknown")
    is_geo_shift = event.get("is_geographic_shift") or False
    is_cold_start = event.get("is_cold_start") or False
    is_inactive_hour = event.get("is_inactive_hour_anomaly") or False
    baseline_country = event.get("baseline_primary_country", "Unknown")
    recent_country = event.get("recent_primary_country", "Unknown")
    if is_geo_shift and is_inactive_hour:
        return (
            f"Okta SWA: Off-Hours Credential Access with Geographic Shift for {admin}"
            f" ({baseline_country} -> {recent_country})"
        )
    if is_cold_start:
        return f"Okta SWA: Credential Access with No Baseline (Cold Start) for {admin}"
    if is_geo_shift:
        return (
            f"Okta SWA: Geographic Shift in Credential Access for {admin}"
            f" ({baseline_country} -> {recent_country})"
        )
    return f"Okta SWA: Off-Hours Credential Access Anomaly for {admin}"


def severity(event):
    is_geo_shift = event.get("is_geographic_shift") or False
    is_inactive_hour = event.get("is_inactive_hour_anomaly") or False
    is_cold_start = event.get("is_cold_start") or False
    z_score = event.get("z_score_inactive_slot_ratio") or 0
    score = event.get("anomaly_severity_score") or 0
    if is_geo_shift and is_inactive_hour:
        return "CRITICAL"
    if is_geo_shift or is_cold_start or z_score > 6 or score > 20:
        return "HIGH"
    if is_inactive_hour:
        return "MEDIUM"
    return "LOW"


def dedup_key(event):
    admin = event.get("admin_email", "unknown")
    first_event = str(event.get("recent_first_event", "unknown"))[:10]
    return f"okta_swa_offhours_{admin}_{first_event}"


def alert_context(event):
    return {
        "admin_email": event.get("admin_email"),
        "recent_total_credential_access": event.get("recent_total_credential_access"),
        "recent_inactive_slot_events": event.get("recent_inactive_slot_events"),
        "recent_inactive_slot_ratio": event.get("recent_inactive_slot_ratio"),
        "recent_avg_inactive_slot_ratio_per_hour": event.get(
            "recent_avg_inactive_slot_ratio_per_hour"
        ),
        "z_score_inactive_slot_ratio": event.get("z_score_inactive_slot_ratio"),
        "baseline_active_slot_count": event.get("baseline_active_slot_count"),
        "is_inactive_hour_anomaly": event.get("is_inactive_hour_anomaly"),
        "is_cold_start": event.get("is_cold_start"),
        "is_geographic_shift": event.get("is_geographic_shift"),
        "baseline_primary_country": event.get("baseline_primary_country"),
        "recent_primary_country": event.get("recent_primary_country"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
        "recent_first_event": event.get("recent_first_event"),
        "recent_last_event": event.get("recent_last_event"),
    }
