from panther_base_helpers import crowdstrike_detection_alert_context
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
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{10,}[=]{0,2}')

    # Normalize the FileName to lower case for comparison
    file_name = event.get("FileName", default="").lower()
    command_line = event.get("CommandLine", default="").lower()

    # Check if the FileName matches any of the command line tools
    # and if Base64 encoded arguments are present in the command line
    if file_name in command_line_tools and base64_pattern.search(command_line):
        return True

    return False


def title(event):
    file_name = event.get("FileName", default="")
    command_line = event.get("CommandLine", default="")

    return f"Execution of Command Line Tool with Base64 Encoded Arguments: {file_name} - {command_line} "


def alert_context(event):
    return crowdstrike_detection_alert_context