import re
from panther_base_helpers import is_base64, lenient_base64_decode
from panther_crowdstrike_fdr_helpers import crowdstrike_process_alert_context


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
    if not all([
        event.get("fdr_event_type") == "ProcessRollup2",
        event.get("event_platform") == "Win",
        (event.udm("process_name") or "").lower() in COMMAND_LINE_TOOLS,
    ]):
        return False

    cmd = event.udm("cmd", default="").replace("\u2013", "-")

    # find all long base64-like tokens (including URL-safe base64 with - and _)
    for match in re.findall(r"[A-Za-z0-9+/=_-]{12,}", cmd):
        # Strip common command-line prefixes (like --flag=, -flag=, etc.)
        # This handles cases like: --b64=aGVsbG8... or -enc=aGVsbG8...
        cleaned_match = re.sub(r'^-+[a-zA-Z0-9_-]*=', '', match)

        # Try multiple base64 variants
        variants = [
            cleaned_match,  # Try cleaned string first
            cleaned_match.replace("-", "+").replace("_", "/"),  # URL-safe to standard base64
            cleaned_match.replace("-", "").replace("_", ""),  # Remove hyphens/underscores (mangled)
        ]

        for variant in variants:
            # Try strict validation first
            decoded = is_base64(variant)
            if not decoded:
                # Fallback to lenient decoding for corrupted/malformed base64
                decoded = lenient_base64_decode(variant)

            if decoded:
                global DECODED
                DECODED = decoded
                return True
    return False




def title(event):
    process_name = event.udm("process_name") if event.udm("process_name") else "Unknown"
    process_name = process_name.lower()
    command_line = event.udm("cmd")
    return f"Crowdstrike: Execution with base64 encoded args: [{process_name}] - [{command_line}]"


def alert_context(event):
    context = crowdstrike_process_alert_context(event)
    context["decoded arg"] = DECODED
    return context
