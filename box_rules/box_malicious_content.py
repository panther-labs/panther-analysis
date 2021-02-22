from panther_base_helpers import box_parse_additional_details, deep_get


def rule(event):
    # enterprise  malicious file alert event
    if event.get("event_type") == "FILE_MARKED_MALICIOUS":
        return True
    # Box Shield will also alert on malicious content
    if event.get("event_type") != "SHIELD_ALERT":
        return False
    alert_details = box_parse_additional_details(event).get("shield_alert", {})
    if alert_details.get("rule_category", "") == "Malicious Content":
        if alert_details.get("risk_score", 0) > 50:
            return True
    return False


def title(event):
    if event.get("event_type") == "FILE_MARKED_MALICIOUS":
        return "File [{}], owned by [{}], was marked malicious.".format(
            deep_get(event, "source", "item_name", default="<UNKNOWN_FILE"),
            deep_get(event, "source", "owned_by", "login", default="<UNKNOWN_USER>"),
        )

    alert_details = box_parse_additional_details(event).get("shield_alert", {})
    return "File [{}], owned by [{}], was marked malicious.".format(
        deep_get(
            alert_details, "alert_summary", "upload_activity", "item_name", default="<UNKNOWN_FILE>"
        ),
        deep_get(alert_details, "user", "email", default="<UNKNOWN_USER>"),
    )
