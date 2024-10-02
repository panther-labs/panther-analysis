from panther_base_helpers import crowdstrike_process_alert_context


def rule(event):
    command_line = event.deep_get("event", "CommandLine", default="<UNKNOWN_COMMAND_LINE>")
    if (
        command_line
        == "plutil -convert binary1 /Library/Preferences/com.tinyspeck.slackmacgap.plist"
    ):
        return False

    event_platform = event.get("event_platform", "<UNKNOWN_PLATFORM>")
    fdr_event_type = event.get("fdr_event_type", "<UNKNOWN_FDR_EVENT_TYPE>")
    image_filename = event.deep_get("event", "ImageFileName", default="<UNKNOWN_IMAGE_FILE_NAME>")

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
