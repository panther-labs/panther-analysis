from panther_base_helpers import crowdstrike_process_alert_context, deep_get


def rule(event):
    event_platform = deep_get(event, "event_platform", default="<UNKNOWN_PLATFORM>")
    event_simplename = deep_get(event, "event_simplename", default="<UNKNOWN_EVENT_SIMPLENAME>")
    image_filename = deep_get(event, "event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")
    command_line = deep_get(event, "event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
    return all(
        [
            event_platform == "Mac",
            event_simplename == "ProcessRollup2",
            image_filename == "/usr/bin/osascript",
            "with administrator privileges" in command_line,
        ]
    )


def title(event):
    aid = event.get("aid", "<UNKNOWN_AID>")
    return f"Crowdstrike: Osascript run with administrator privileges on [{aid}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
