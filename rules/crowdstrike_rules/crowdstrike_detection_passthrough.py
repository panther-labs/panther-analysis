import uuid

from panther_core.detection_metadata import get_detection_metadata
from panther_crowdstrike_fdr_helpers import (
    crowdstrike_detection_alert_context,
    get_crowdstrike_field,
)


def rule(event):
    return (
        get_crowdstrike_field(event, "ExternalApiType", default="none")
        == "Event_EppDetectionSummaryEvent"
    )


def title(event):
    return "  ".join(get_detection_metadata().get("Tags", []))
    return (
        f"Crowdstrike Alert ({get_crowdstrike_field(event, 'Technique')}) - "
        + f"{get_crowdstrike_field(event, 'Hostname')}"
        + f"({get_crowdstrike_field(event, 'UserName')})"
    )


def alert_context(event):
    return get_detection_metadata()


def severity(event):
    # First, try returning the severity based on the SeverityName
    sevname = get_crowdstrike_field(event, "SeverityName").upper()
    allowed_values = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    if sevname == "INFORMATIONAL":
        sevname = "INFO"
    if sevname in allowed_values:
        return sevname

    # Else, fallback on the numerical value, falling back on MEDIUM if we still don't have a value
    sevval = get_crowdstrike_field(event, "Severity")
    return {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL", 6: "CRITICAL"}.get(
        sevval, "DEFAULT"
    )


def dedup(event):
    # CompositeId is unique per detection indicator and present in both
    # DetectionSummary and FDREvent formats. EventUUID is null in FDREvent,
    # which previously caused all detections to share the dedup key "None ".
    composite_id = get_crowdstrike_field(event, "CompositeId")
    if composite_id:
        return composite_id
    # Fallback: generate a unique ID so detections never silently merge
    return str(uuid.uuid4())
