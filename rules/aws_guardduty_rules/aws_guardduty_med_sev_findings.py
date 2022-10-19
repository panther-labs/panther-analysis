def rule(event):
    return 4.0 <= float(event.get("severity", 0)) <= 6.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")


def alert_context(event):
    return {
        "description": event.get("description", "<MISSING DESCRIPTION>"),
        "severity": event.get("severity", "<MISSING SEVERITY>"),
        "id": event.get("id", "<MISSING ID>"),
        "type": event.get("type", "<MISSING TYPE>"),
        "resource": event.get("resource", {}),
        "service": event.get("service", {}),
    }
