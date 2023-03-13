from panther_base_helpers import okta_alert_context, deep_get


def severity_from_threat_string(threat_detection):
    # threat detection is a string but contains json data
    # can contain multiple threats detected with multiple severities
    # return highest found severity
    if "CRITICAL" in threat_detection:
        return "CRITICAL"
    if "HIGH" in threat_detection:
        return "HIGH"
    if "MEDIUM" in threat_detection:
        return "MEDIUM"
    if "LOW" in threat_detection:
        return "LOW"
    if "INFO" in threat_detection:
        return "INFO"
    return "MEDIUM"


def rule(event):
    return event.get("eventtype") == "security.threat.detected"


def title(event):
    return (
        "Okta: ThreatInsight identified potentially malicious behavior"
        f" for [{event.get('actor',{}).get('displayName', '<display-name-not-found>')}]"
    )


def severity(event):
    outcome = deep_get(event, "outcome", "result", default="<OUTCOME_NOT_FOUND>")
    if outcome == "DENY":
        return "INFO"
    threat_detection = (
        event.get("debugcontext", {})
        .get("debugData", {})
        .get("threatDetections", "<threat-detection-not-found>")
    )
    return severity_from_threat_string(threat_detection)


def alert_context(event):
    return okta_alert_context(event)
