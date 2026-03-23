SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}


def rule(event):
    return event.get("status") != "CLOSED"


def title(event):
    main_type = event.deep_get("alarm_type_details", "alarm_main_type", default="Unknown")
    sub_type = event.deep_get("alarm_type_details", "alarm_sub_type", default="")
    risk = event.get("alarm_risk_level", "UNKNOWN")
    return f"SOCRadar {risk} [{main_type} - {sub_type}]"


def severity(event):
    risk = event.get("alarm_risk_level", "").upper()
    return SEVERITY_MAP.get(risk, "Medium")


def dedup(event):
    return str(event.get("alarm_id", ""))


def alert_context(event):
    context = {
        "alarm_id": event.get("alarm_id"),
        "alarm_asset": event.get("alarm_asset"),
        "alarm_text": event.get("alarm_text"),
        "main_type": event.deep_get("alarm_type_details", "alarm_main_type"),
        "sub_type": event.deep_get("alarm_type_details", "alarm_sub_type"),
        "status": event.get("status"),
        "mitigation": event.deep_get("alarm_type_details", "alarm_default_mitigation_plan"),
    }

    content = event.get("content") or {}
    for field in (
        "content_link",
        "phishing_domain",
        "phishing_domain_url",
        "compromised_emails",
        "compromised_ips",
        "compromised_domains",
        "malware_family",
        "computer_name",
        "username",
        "source",
        "content_preview",
    ):
        if content.get(field):
            context[field] = content[field]

    return context
