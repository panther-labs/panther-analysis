def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("admin_email"))


def title(event):
    admin = event.get("admin_email", "Unknown")
    recent_extractions = event.get("recent_total_extractions") or 0
    recent_swa_events = event.get("recent_total_swa_events") or 0
    has_new_ip = event.get("has_new_ip") or False
    new_ip_extraction_count = event.get("new_ip_extraction_count") or 0
    if recent_extractions > 0 and has_new_ip:
        return (
            f"Okta SWA: Credential Extraction from New IP by {admin}"
            f" ({new_ip_extraction_count} extractions from new source)"
        )
    if recent_extractions > 0:
        return f"Okta SWA: Bulk Credential Extraction by {admin} ({recent_extractions} extractions)"
    if has_new_ip:
        return f"Okta SWA: Access from New IP by {admin} ({recent_swa_events} events)"
    return f"Okta SWA: Bulk App Access Anomaly by {admin} ({recent_swa_events} events)"


def severity(event):
    is_first_extraction = event.get("is_first_time_credential_extraction") or False
    is_extraction_anomaly = event.get("is_extraction_volume_anomaly") or False
    is_victim_anomaly = event.get("is_victim_diversity_anomaly") or False
    recent_extractions = event.get("recent_total_extractions") or 0
    has_new_ip = event.get("has_new_ip") or False
    has_new_user_agent = event.get("has_new_user_agent") or False
    new_ip_extraction_count = event.get("new_ip_extraction_count") or 0
    score = event.get("anomaly_severity_score") or 0
    if has_new_ip and new_ip_extraction_count > 0:
        return "CRITICAL"
    if is_first_extraction or is_extraction_anomaly or is_victim_anomaly:
        return "CRITICAL"
    if has_new_ip or recent_extractions > 0 or score > 20:
        return "HIGH"
    if has_new_user_agent:
        return "MEDIUM"
    return "MEDIUM"


def alert_context(event):
    return {
        "admin_email": event.get("admin_email"),
        "recent_total_extractions": event.get("recent_total_extractions"),
        "recent_max_victim_diversity_per_hour": event.get("recent_max_victim_diversity_per_hour"),
        "recent_total_swa_events": event.get("recent_total_swa_events"),
        "recent_max_app_diversity_per_hour": event.get("recent_max_app_diversity_per_hour"),
        "z_score_extraction_volume": event.get("z_score_extraction_volume"),
        "z_score_victim_diversity": event.get("z_score_victim_diversity"),
        "z_score_swa_volume": event.get("z_score_swa_volume"),
        "has_new_ip": event.get("has_new_ip"),
        "has_new_user_agent": event.get("has_new_user_agent"),
        "new_ip_count": event.get("new_ip_count"),
        "new_ip_extraction_count": event.get("new_ip_extraction_count"),
        "new_ip_victim_count": event.get("new_ip_victim_count"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
        "is_first_time_credential_extraction": event.get("is_first_time_credential_extraction"),
        "recent_extraction_first_event": event.get("recent_extraction_first_event"),
        "recent_extraction_last_event": event.get("recent_extraction_last_event"),
    }
