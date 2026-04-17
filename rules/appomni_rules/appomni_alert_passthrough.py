SEV_DICT = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Info"}


def rule(event):
    # Only alert where event.kind == "alert"
    if event.deep_get("event", "kind") == "alert":
        return True
    return False


def title(event):
    # Create title that includes severity and message
    sev = SEV_DICT.get(event.deep_get("event", "severity"))

    # Use type service in title if only one field, label as 'Multiple Services' if more than one.
    if len(event.deep_get("related", "services", "type", default=[])) == 1:
        service = event.deep_get("related", "services", "type")[0]
    else:
        service = "Multiple Services"

    return f'[{sev}] - {service} - {event.get("message")}'


def severity(event):
    # Update Panther alert severity based on severity from AppOmni Alert
    return SEV_DICT[event.deep_get("event", "severity", default=4)]


def dedup(event):
    # Dedup by the events alert id, make sure we alert each time a new AppOmni alert is logged
    return f'Event ID: {event.deep_get("appomni", "event", "id")}'


def alert_context(event):
    # 'Threat' and 'related' data to be included in the alert sent to the alert destination
    return {"threat": event.deep_get("rule", "threat"), "related": event.get("related")}
