from base64 import b64decode
from binascii import Error as AsciiError

from panther_base_helpers import crowdstrike_process_alert_context

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
    # Filter by CS event type, Windows platform, and process name
    if not all(
        [
            event.get("fdr_event_type") == "ProcessRollup2",
            event.get("event_platform") == "Win",
            event.udm("process_name").lower() in COMMAND_LINE_TOOLS,
        ]
    ):
        return False

    # Split arguments from process path
    command_line_args = event.udm("cmd")
    command_line_args = command_line_args.replace('"', "")
    command_line_args = command_line_args.replace("'", "")
    command_line_args = command_line_args.split(" ")[1:]

    # Check if Base64 encoded arguments are present in the command line
    for arg in command_line_args:
        try:
            # Check if the matched string can be decoded back into ASCII
            global DECODED
            DECODED = b64decode(arg).decode("ascii")
            if len(DECODED) > 0:
                return True
        except AsciiError:
            continue
        except UnicodeDecodeError:
            continue

    return False


def title(event):
    process_name = event.udm("process_name").lower()
    command_line = event.udm("cmd")
    return f"Crowdstrike: Execution with base64 encoded args: [{process_name}] - [{command_line}]"


def alert_context(event):
    context = crowdstrike_process_alert_context(event)
    context["decoded arg"] = DECODED
    return context
