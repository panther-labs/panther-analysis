import re

from panther_base_helpers import crowdstrike_process_alert_context


def rule(event):
    # List of command line tools to monitor for execution with Base64 encoded arguments
    command_line_tools = {
        "powershell.exe",
        "cmd.exe",
        "cscript.exe",
        "wscript.exe",
        "rundll32.exe",
    }

    # Filter by CS event type
    if event.get("fdr_event_type") != "ProcessRollup2":
        return False

    # Define a regular expression pattern to match Base64 encoded strings

    if event.get("event_platform") == "Win":
        base64_pattern = re.compile(
            r"^(\W|)(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?(\W|)$"
        )

        # Normalize the process name to lower case for comparison
        process_name = event.udm("process_name").lower()
        # Split process path from arguments
        command_line_args = event.udm("cmd").split(" ")[1:]

        # Check if the process name matches any of the command line tools
        # and if Base64 encoded arguments are present in the command line
        if process_name in command_line_tools:
            for arg in command_line_args:
                if base64_pattern.search(arg):
                    return True
    return False


def title(event):
    process_name = event.udm("process_name").lower()
    command_line = event.udm("cmd").lower()

    return f"Crowdstrike: Execution with base64 encoded args: [{process_name}] - [{command_line}]"


def alert_context(event):
    return crowdstrike_process_alert_context(event)
