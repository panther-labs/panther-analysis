from panther_crowdstrike_fdr_helpers import crowdstrike_process_alert_context


def rule(event):
    event_platform = event.get("event_platform", "<UNKNOWN_PLATFORM>")
    fdr_event_type = event.get("fdr_event_type", "<UNKNOWN_FDR_EVENT_TYPE>")
    image_filename = event.deep_get("event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")
    command_line = event.deep_get("event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
    return all(
        [
            event_platform == "Mac",
            fdr_event_type == "ProcessRollup2",
            image_filename == "/usr/bin/security",
            "add-trusted-cert" in command_line,
        ]
    )


def title(event):
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: New trusted cert added on device [{host}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
