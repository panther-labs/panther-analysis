from panther_crowdstrike_fdr_helpers import crowdstrike_process_alert_context


def rule(event):
    event_platform = event.get("event_platform", "<UNKNOWN_PLATFORM>")
    event_simplename = event.get("event_simplename", "<UNKNOWN_EVENT_SIMPLENAME>")
    image_filename = event.deep_get("event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")
    command_line = event.deep_get("event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
    return all(
        [
            event_platform == "Mac",
            event_simplename == "ProcessRollup2",
            image_filename == "/usr/bin/osascript",
            "with administrator privileges" in command_line,
        ]
    )


def title(event):
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Osascript run with administrator privileges on [{host}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
