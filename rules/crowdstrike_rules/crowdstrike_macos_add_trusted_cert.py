from panther_base_helpers import crowdstrike_process_alert_context, deep_get


def rule(event):
    event_platform = deep_get(event, "event_platform", default="<UNKNOWN_PLATFORM>")
    fdr_event_type = deep_get(event, "fdr_event_type", default="<UNKNOWN_FDR_EVENT_TYPE>")
    image_filename = deep_get(event, "event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")
    command_line = deep_get(event, "event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
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
