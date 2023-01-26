from panther_base_helpers import crowdstrike_detection_alert_context, get_crowdstrike_field


def rule(event):
    return (
        get_crowdstrike_field(event, "ExternalApiType", default="none")
        == "Event_DetectionSummaryEvent"
    )


def title(event):
    # pylint: disable=line-too-long
    return f"Crowdstrike Alert ({get_crowdstrike_field(event, 'Technique')}) - {get_crowdstrike_field(event, 'ComputerName')}({get_crowdstrike_field(event, 'UserName')})"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)


def severity(event):
    return get_crowdstrike_field(event, "SeverityName")


def dedup(event):
    # pylint: disable=line-too-long
    return f"{get_crowdstrike_field(event, 'EventUUID')} - {get_crowdstrike_field(event, 'ComputerName')}"
