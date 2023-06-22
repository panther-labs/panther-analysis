from panther_base_helpers import crowdstrike_process_alert_context, deep_get


def rule(event):
    command_line = deep_get(event, "event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
    if (
        command_line
        == "plutil -convert binary1 /Library/Preferences/com.tinyspeck.slackmacgap.plist"
    ):
        return False

    event_platform = deep_get(event, "event_platform", default="<UNKNOWN_PLATFORM>")
    fdr_event_type = deep_get(event, "fdr_event_type", default="<UNKNOWN_FDR_EVENT_TYPE>")
    image_filename = deep_get(event, "event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")

    return all(
        [
            event_platform == "Mac",
            fdr_event_type == "ProcessRollup2",
            image_filename == "/usr/bin/plutil",
        ]
    )


def title(event):
    aid = event.get("aid", "<UNKNOWN_AID>")
    return f"Crowdstrike: plutil was used to modify a plist file on device [{aid}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
