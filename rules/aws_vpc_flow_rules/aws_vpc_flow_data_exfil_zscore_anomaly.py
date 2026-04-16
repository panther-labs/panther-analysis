def rule(event):
    # Query already filtered for anomalies (is_anomalous = TRUE OR is_cold_start_anomaly = TRUE).
    # Guard against malformed rows missing the primary key field.
    return bool(event.get("account_id"))


def title(event):
    account_id = event.get("account_id", "<UNKNOWN_ACCOUNT>")
    severity_score = event.get("anomaly_severity_score", 0)
    is_cold_start = event.get("is_cold_start_anomaly", False)

    if is_cold_start:
        return (
            f"VPC Flow Log Data Exfiltration Anomaly (Cold Start): Account {account_id} "
            f"shows high-volume outbound traffic with no established baseline"
        )
    return (
        f"VPC Flow Log Data Exfiltration Anomaly: Account {account_id} "
        f"(Severity Score: {severity_score})"
    )


def severity(event):
    # Dynamic severity based on anomaly severity score and z-score magnitudes.
    # Higher z-scores = more standard deviations from baseline = more suspicious.
    # Cold-start events have null z-scores (no baseline), so default to 0.
    severity_score = event.get("anomaly_severity_score") or 0
    z_bytes = event.get("z_score_bytes") or 0
    z_dst_ip = event.get("z_score_dst_ip_diversity") or 0
    z_src_ip = event.get("z_score_src_ip_diversity") or 0

    # Critical: Extreme anomaly (severity score > 15 or any key z-score > 5)
    if severity_score > 15 or max(z_bytes, z_dst_ip, z_src_ip) > 5:
        return "CRITICAL"

    # High: Strong anomaly (severity score > 10 or any key z-score > 4)
    if severity_score > 10 or max(z_bytes, z_dst_ip, z_src_ip) > 4:
        return "HIGH"

    # Medium: Moderate anomaly (default for detections that passed threshold)
    return "MEDIUM"


def alert_context(event):
    return {
        # Account context
        "account_id": event.get("account_id", "<UNKNOWN_ACCOUNT>"),
        # Baseline behavior
        "baseline_total_bytes": event.get("baseline_total_bytes", 0),
        "baseline_active_days": event.get("baseline_active_days", 0),
        "baseline_mean_bytes_per_hour": event.get("baseline_mean_bytes_per_hour", 0),
        "baseline_mean_dst_ip_diversity": event.get("baseline_mean_dst_ip_diversity_per_hour", 0),
        "baseline_mean_src_ip_diversity": event.get("baseline_mean_src_ip_diversity_per_hour", 0),
        "primary_dst_ip": event.get("primary_dst_ip"),
        # Recent anomalous activity
        "recent_total_bytes": event.get("recent_total_bytes", 0),
        "recent_max_bytes_per_hour": event.get("recent_max_bytes_per_hour", 0),
        "recent_max_dst_ip_diversity": event.get("recent_max_dst_ip_diversity_per_hour", 0),
        "recent_max_dst_port_diversity": event.get("recent_max_dst_port_diversity_per_hour", 0),
        "recent_max_src_ip_diversity": event.get("recent_max_src_ip_diversity_per_hour", 0),
        # Z-scores (standard deviations from baseline)
        "z_score_bytes": event.get("z_score_bytes", 0),
        "z_score_flows": event.get("z_score_flows", 0),
        "z_score_dst_ip_diversity": event.get("z_score_dst_ip_diversity", 0),
        "z_score_dst_port_diversity": event.get("z_score_dst_port_diversity", 0),
        "z_score_src_ip_diversity": event.get("z_score_src_ip_diversity", 0),
        "anomaly_severity_score": event.get("anomaly_severity_score", 0),
        # Network context
        "recent_dst_ips": event.get("all_recent_dst_ips", []),
        # Temporal context
        "first_anomaly_hour": event.get("first_anomaly_hour", "<UNKNOWN>"),
        "last_anomaly_hour": event.get("last_anomaly_hour", "<UNKNOWN>"),
        "detection_timestamp": event.get("detection_timestamp", "<UNKNOWN>"),
        "is_cold_start_anomaly": event.get("is_cold_start_anomaly", False),
    }


def dedup_key(event):
    # Deduplicate by account and first anomaly hour to avoid alert spam during active attacks.
    account = event.get("account_id", "unknown")
    first_hour = str(event.get("first_anomaly_hour", "unknown"))
    return f"vpc_flow_data_exfil_zscore_{account}_{first_hour}"
