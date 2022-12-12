from panther_base_helpers import crowdstrike_detections_alert_context # Don't know if I need this


def rule(event):
    return event.get("ExternalApiType") in "Event_RemoteResponseSessionStartEvent"


def title(event):
    return f"{UserName} started a Crowdstrike Real-Time Response (RTR) shell on {HostnameField}"


def alert_context(event):
    return {
        "StartTimestamp": event.get("StartTimestamp"),
        "SessionId": event.get("sessionId"),
        "UserName": event.get("UserName"),
        "HostnameField": event.get("HostnameField"),
    }


def severity(event):
    return event.get("SeverityName")
