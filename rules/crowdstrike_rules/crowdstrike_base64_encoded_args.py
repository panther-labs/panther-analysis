from panther_base_helpers import crowdstrike_process_alert_context
import re

def rule(event):
    # List of command line tools to monitor for execution with Base64 encoded arguments
    command_line_tools = {
        "powershell.exe",
        "cmd.exe",
        "cscript.exe",
        "wscript.exe",
        "rundll32.exe",
    }

    # Define a regular expression pattern to match Base64 encoded strings
    base64_pattern = re.compile(r"[A-Za-z0-9+/]{10,}[=]{0,2}")

    # Normalize the process name to lower case for comparison
    process_name = event.udm("process_name").lower()
    # Split process path from arguments
    command_line_args = " ".join(event.udm("cmd").split(" ")[1:])

    # Check if the process name matches any of the command line tools
    # and if Base64 encoded arguments are present in the command line
    if process_name in command_line_tools and base64_pattern.search(command_line_args):
        return True
    return False


def title(event):
    process_name = event.udm("process_name").lower()
    command_line = event.udm("cmd").lower()

    return f"Execution with base64 encoded args: {process_name} - {command_line} "


def alert_context(event):
    return crowdstrike_process_alert_context(event)
