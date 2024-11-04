def crowdstrike_detection_alert_context(event):
    """Returns common context for Crowdstrike detections"""
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "user": get_crowdstrike_field(event, "UserName", default=""),
        "console-link": get_crowdstrike_field(event, "FalconHostLink", default=""),
        "commandline": get_crowdstrike_field(event, "CommandLine", default=""),
        "parentcommandline": get_crowdstrike_field(event, "ParentCommandLine", default=""),
        "filename": get_crowdstrike_field(event, "FileName", default=""),
        "filepath": get_crowdstrike_field(event, "FilePath", default=""),
        "description": get_crowdstrike_field(event, "DetectDescription", default=""),
        "action": get_crowdstrike_field(event, "PatternDispositionDescription", default=""),
    }


def crowdstrike_process_alert_context(event):
    """Returns common process context for Crowdstrike detections"""
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "CommandLine": get_crowdstrike_field(event, "CommandLine", default=""),
        "TargetProcessId": get_crowdstrike_field(event, "TargetProcessId", default=""),
        "RawProcessId": get_crowdstrike_field(event, "RawProcessId", default=""),
        "ParentBaseFileName": get_crowdstrike_field(event, "ParentBaseFileName", default=""),
        "ParentProcessId": get_crowdstrike_field(event, "ParentProcessId", default=""),
        "ImageFileName": get_crowdstrike_field(event, "ImageFileName", default=""),
        "SHA256Hash": get_crowdstrike_field(event, "SHA256HashData", default=""),
        "platform": get_crowdstrike_field(event, "event_platform", default=""),
    }


def crowdstrike_network_detection_alert_context(event):
    """Returns common network context for Crowdstrike detections"""
    return {
        "LocalAddressIP4": get_crowdstrike_field(event, "LocalAddressIP4", default=""),
        "LocalPort": get_crowdstrike_field(event, "LocalPort", default=""),
        "RemoteAddressIP4": get_crowdstrike_field(event, "RemoteAddressIP4", default=""),
        "RemotePort": get_crowdstrike_field(event, "RemotePort", default=""),
        "Protocol": get_crowdstrike_field(event, "Protocol", default=""),
        "event_simpleName": get_crowdstrike_field(event, "event_simpleName", default=""),
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "ContextProcessId": get_crowdstrike_field(event, "ContextProcessId", default=""),
    }


def filter_crowdstrike_fdr_event_type(event, name: str) -> bool:
    """
    Checks if the event belongs to the Crowdstrike.FDREvent log type
    and the event type is not the name parameter.
    """
    if event.get("p_log_type") != "Crowdstrike.FDREvent":
        return False
    return event.get("fdr_event_type", "") != name


def get_crowdstrike_field(event, field_name, default=None):
    return (
        event.deep_get(field_name)
        or event.deep_get("event", field_name)
        or event.deep_get("unknown_payload", field_name)
        or default
    )
