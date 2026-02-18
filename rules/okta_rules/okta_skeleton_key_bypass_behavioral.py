def rule(_):
    # Query already filtered for anomalies
    return True


def title(event):
    actor = event.get("actorId", "<UNKNOWN_ACTOR>")
    target_app = event.get("targetApp", "<UNKNOWN_APP>")
    anomaly_type = event.get("anomaly_type", "Unknown Anomaly")

    return f"Okta SSO from {anomaly_type}: {actor} accessed {target_app}"


def severity(event):
    device_type = event.get("deviceType", "").lower()
    user_agent = event.get("userAgent", "").lower()

    # Unknown devices are high risk
    if device_type == "unknown":
        return "HIGH"

    # Automation tools are high risk
    automation_indicators = ["python", "curl", "wget", "postman", "httpie"]
    if any(indicator in user_agent for indicator in automation_indicators):
        return "HIGH"

    return "DEFAULT"


def alert_context(event):
    return {
        "actor_id": event.get("actorId", "<UNKNOWN_ACTORID>"),
        "actor_name": event.get("actorName", "<UNKNOWN_ACTORNAME>"),
        "source_ip": event.get("sourceIP", "<UNKNOWN_SOURCEIP>"),
        "device_type": event.get("deviceType", "<UNKNOWN_DEVICETYPE>"),
        "user_agent": event.get("userAgent", "<UNKNOWN_USERAGENT>"),
        "browser": event.get("browser", "<UNKNOWN_BROWSER>"),
        "operating_system": event.get("operatingSystem", "<UNKNOWN_OS>"),
        "target_app": event.get("targetApp", "<UNKNOWN_TARGETAPP>"),
        "target_app_id": event.get("targetAppId", "<UNKNOWN_TARGETAPPID>"),
        "anomaly_type": event.get("anomaly_type", "<UNKNOWN_ANOMALYTYPE>"),
        "event_time": event.get("p_event_time", "<UNKNOWN_EVENTTIME>"),
    }
