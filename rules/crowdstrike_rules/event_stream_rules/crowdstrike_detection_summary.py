from panther_crowdstrike_event_streams_helpers import cs_alert_context


def rule(event):
    return event.deep_get("metadata", "eventType") == "EppDetectionSummaryEvent"


def title(event):
    alert_title = event.deep_get("event", "Name", default="New CrowdStrike Detection")
    alert_desc = event.deep_get("event", "Description")
    return f"{alert_title}: {alert_desc}" if alert_desc else alert_title


def dedup(event):
    if alert_id := event.deep_get("event", "CompositeId"):
        return alert_id
    # Else, fall back on title string
    return title(event)


def severity(event):
    # First, try returning the severity based on the SeverityName
    sevname = event.deep_get("event", "SeverityName").upper()
    allowed_values = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    if sevname == "INFORMATIONAL":
        sevname = "INFO"
    if sevname in allowed_values:
        return sevname

    # Else, fallback on the numerical value, falling back on MEDIUM if we still don't have a value
    sevval = event.deep_get("event", "Severity") // 20
    return {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "CRITICAL"}.get(
        sevval, "MEDIUM"
    )


def alert_context(event):
    context = cs_alert_context(event)
    context.update(
        {"FalconLink": event.deep_get("event", "FalconHostLink", default="<NO LINK PROVIDED>")}
    )
    return context
