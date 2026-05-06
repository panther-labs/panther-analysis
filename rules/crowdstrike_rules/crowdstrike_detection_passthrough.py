import uuid

from panther_crowdstrike_fdr_helpers import (
    crowdstrike_detection_alert_context,
    crowdstrike_severity,
    get_crowdstrike_field,
)


def rule(event):
    return (
        get_crowdstrike_field(event, "ExternalApiType", default="none")
        == "Event_EppDetectionSummaryEvent"
    )


def title(event):
    return (
        f"Crowdstrike Alert ({get_crowdstrike_field(event, 'Technique')}) - "
        + f"{get_crowdstrike_field(event, 'Hostname')}"
        + f"({get_crowdstrike_field(event, 'UserName')})"
    )


def alert_context(event):
    return crowdstrike_detection_alert_context(event)


def severity(event):
    return crowdstrike_severity(event)


def dedup(event):
    # CompositeId is unique per detection indicator and present in both
    # DetectionSummary and FDREvent formats. EventUUID is null in FDREvent,
    # which previously caused all detections to share the dedup key "None ".
    composite_id = get_crowdstrike_field(event, "CompositeId")
    if composite_id:
        return composite_id
    # Fallback: generate a unique ID so detections never silently merge
    return str(uuid.uuid4())
