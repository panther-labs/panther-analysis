def rule(event):
    # Query already filtered for is_anomalous = TRUE.
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("admin_email"))


def title(event):
    admin = event.get("admin_email", "Unknown")
    recent_weakenings = event.get("recent_total_weakenings") or 0
    recent_admin_enrollments = event.get("recent_total_admin_enrollments") or 0
    if recent_weakenings > 0:
        return f"Okta Skeleton Key: Security Policy Weakening by {admin}"
    if recent_admin_enrollments > 0:
        return f"Okta Skeleton Key: Bulk Admin Factor Enrollment by {admin}"
    return f"Okta Skeleton Key Bypass Anomaly Detected for {admin}"


def severity(event):
    score = event.get("anomaly_severity_score") or 0
    is_first_security_weakening = event.get("is_first_time_security_weakening") or False
    recent_weakenings = event.get("recent_total_weakenings") or 0
    if is_first_security_weakening or (recent_weakenings > 0 and score > 20):
        return "CRITICAL"
    if recent_weakenings > 0 or score > 15:
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return {
        "admin_email": event.get("admin_email"),
        "recent_total_weakenings": event.get("recent_total_weakenings"),
        "recent_total_admin_enrollments": event.get("recent_total_admin_enrollments"),
        "z_score_security_weakenings": event.get("z_score_security_weakenings"),
        "z_score_admin_enrollments": event.get("z_score_admin_enrollments"),
        "anomaly_severity_score": event.get("anomaly_severity_score"),
        "is_first_time_security_weakening": event.get("is_first_time_security_weakening"),
        "is_first_time_admin_enrollment": event.get("is_first_time_admin_enrollment"),
        "baseline_total_weakenings": event.get("baseline_total_weakenings"),
        "recent_policy_first_event": event.get("recent_policy_first_event"),
        "recent_policy_last_event": event.get("recent_policy_last_event"),
    }
