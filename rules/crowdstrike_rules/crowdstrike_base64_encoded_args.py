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

# PowerShell flags that signal the following argument is base64-encoded.
# Includes the full parameter name and common abbreviations used in the wild.
# Scanning all tokens without this check causes FPs on legitimate -Command invocations
# whose natural language arguments happen to pass base64 charset validation.
POWERSHELL_ENCODING_FLAGS = {"-encodedcommand", "-enc", "-en", "-e", "-ec"}


def _tokenize_command_line(cmd: str) -> list:
    """Normalize and split a command line string into tokens, skipping the process path."""
    cmd = cmd.replace("\u2013", "-")
    cmd = cmd.replace('"', " ")
    cmd = cmd.replace("'", " ")
    cmd = cmd.replace("=", " ")
    return cmd.split(" ")[1:]


def _find_powershell_encoded_arg(tokens: list) -> str:
    """Return the decoded value of the argument following a PowerShell encoding flag, or ''."""
    for i, arg in enumerate(tokens):
        if arg.lower() in POWERSHELL_ENCODING_FLAGS:
            # Skip empty tokens introduced by quote/equals stripping (e.g. -enc "b64==")
            j = i + 1
            while j < len(tokens) and tokens[j] == "":
                j += 1
            if j < len(tokens):
                decoded = is_base64(tokens[j], min_length=12)
                if decoded:
                    return decoded
    return ""


def _find_base64_token(tokens: list) -> str:
    """Return the first decoded base64 token found, or ''."""
    for arg in tokens:
        decoded = is_base64(arg, min_length=12)
        if decoded:
            return decoded
    return ""


def rule(event):
    # pylint: disable=global-statement
    global DECODED

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

    tokens = _tokenize_command_line(event.udm("cmd", default=""))

    # For PowerShell, base64 only appears as the argument immediately following an
    # encoding flag. Only evaluate that specific token rather than every token,
    # which would cause FPs on -Command invocations with plain English arguments.
    if process_name.lower() == "powershell.exe":
        DECODED = _find_powershell_encoded_arg(tokens)
    else:
        # For other tools (cmd.exe, rundll32.exe, etc.) base64 can appear anywhere
        DECODED = _find_base64_token(tokens)

    return bool(DECODED)


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
