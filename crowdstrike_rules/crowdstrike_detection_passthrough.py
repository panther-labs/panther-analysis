from panther_base_helpers import crowdstrike_detection_alert_context


def rule(event):
    return event.get("ExternalApiType") in "Event_DetectionSummaryEvent"


def title(event):
    # pylint: disable=line-too-long
    return f"Crowdstrike Alert ({event.get('Technique')}) - {event.get('ComputerName')}({event.get('UserName')})"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)


def severity(event):
    return event.get("SeverityName")

def dedup (event):
    return f"{event.get('EventUUID')} - {event.get('ComputerName')}"
