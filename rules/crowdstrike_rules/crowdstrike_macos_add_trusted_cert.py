from panther_base_helpers import crowdstrike_process_alert_context


def rule(event):
    event_platform = event.deep_get("event_platform", default="<UNKNOWN_PLATFORM>")
    fdr_event_type = event.deep_get("fdr_event_type", default="<UNKNOWN_FDR_EVENT_TYPE>")
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
    aid = event.get("aid", "<UNKNOWN_AID>")
    return f"Crowdstrike: New trusted cert added on device [{aid}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
