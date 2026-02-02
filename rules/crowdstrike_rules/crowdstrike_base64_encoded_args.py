from panther_base_helpers import is_base64
from panther_crowdstrike_fdr_helpers import crowdstrike_process_alert_context, get_crowdstrike_field

DECODED = ""

# List of command line tools to monitor for execution with Base64 encoded arguments
COMMAND_LINE_TOOLS = {
    "powershell.exe",
    "cmd.exe",
    "cscript.exe",
    "wscript.exe",
    "rundll32.exe",
}


def rule(event):
    # If there is no process name available (or the CrowdStrike data model is missing) don't alert
    process_name = event.udm("process_name")
    if not process_name:
        return False

    # Filter by CS event type, Windows platform, and process name
    if not all(
        [
            event.get("fdr_event_type") == "ProcessRollup2",
            event.get("event_platform") == "Win",
            process_name.lower() in COMMAND_LINE_TOOLS,
        ]
    ):
        return False

    # Split arguments from process path
    command_line_args = event.udm("cmd", default="")
    command_line_args = command_line_args.replace("\u2013", "-")
    command_line_args = command_line_args.replace('"', " ")
    command_line_args = command_line_args.replace("'", " ")
    command_line_args = command_line_args.replace("=", " ")
    command_line_args = command_line_args.split(" ")[1:]

    # Check if Base64 encoded arguments are present in the command line
    for arg in command_line_args:
        # pylint: disable=global-statement
        global DECODED
        # Use min_length=12 for command-line args (malicious commands can be shorter)
        DECODED = is_base64(arg, min_length=12)
        if DECODED:
            return True

    return False


def title(event):
    process_name = event.udm("process_name") if event.udm("process_name") else "Unknown"
    process_name = process_name.lower()
    parent_process_name = get_crowdstrike_field(event, "ParentBaseFileName", default="Unknown")
    parent_process_name = parent_process_name.lower()
    return (
        "Crowdstrike: Execution with base64 encoded args: "
        + f"[{parent_process_name}] -> [{process_name}]"
    )


def alert_context(event):
    context = crowdstrike_process_alert_context(event)
    context["decoded arg"] = DECODED
    return context
