def rule(_):
    # Query already filtered for anomalies
    return True


def title(event):
    actor = event.get("actorId", "<UNKNOWN_ACTOR>")
    event_type = event.get("eventType", "<UNKNOWN_EVENT>")
    anomaly_type = event.get("anomaly_type", "Unknown Anomaly")

    return f"Okta AD Agent Activity from {anomaly_type}: {actor} - {event_type}"


def severity(event):
    event_type = event.get("eventType", "")

    # New agent registration is critical (potential rogue agent)
    if "agent_instance_added" in event_type:
        return "CRITICAL"

    # Token creation from new source is high severity
    if "api_token.create" in event_type:
        return "HIGH"

    # Config changes and auth failures are medium-high severity
    if "config_change" in event_type or "bad_credentials" in event_type:
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    return {
        "actor_id": event.get("actorId", "<UNKNOWN_ACTORID>"),
        "actor_name": event.get("actorName", "<UNKNOWN_ACTORNAME>"),
        "event_type": event.get("eventType", "<UNKNOWN_EVENTTYPE>"),
        "source_ip": event.get("sourceIP", "<UNKNOWN_SOURCEIP>"),
        "user_agent": event.get("userAgent", "<UNKNOWN_USERAGENT>"),
        "anomaly_type": event.get("anomaly_type", "<UNKNOWN_ANOMALYTYPE>"),
        "target": event.get("target", []),
        "event_time": event.get("p_event_time", "<UNKNOWN_EVENTTIME>"),
    }
