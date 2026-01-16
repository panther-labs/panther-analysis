import re

CREDENTIAL_DUMPING_TOOLS = {
    "mimikatz.exe",
    "secretsdump.py",
    "pwdump.exe",
    "fgdump.exe",
    "gsecdump.exe",
    "samdump2.exe",
    "quarks-pwdump.exe",
    "cachedump.exe",
    "lsadump.exe",
    "procdump.exe",
    "procdump64.exe",
    "mimipenguin.sh",
    "mimidogz.ps1",
    "logonpasswords.exe",
    "pypykatz.exe",
    "dsusers.py",
    "ntdsgrab.py",
    "lazagne.exe",
    "creddump7.exe",
    "keethief.ps1",
    "inveigh.exe",
    "sharpkatz.exe",
    "dumpert.exe",
    "hivedump.exe",
    "kerbrute.exe",
    "sessiongopher.ps1",
    "GoTokenTheft.exe",
}


def normalize_username(username):
    """
    Normalize username for correlation matching by removing special characters
    and converting to lowercase.
    Examples: Jane.Doe -> janedoe, john_smith -> johnsmith
    """
    if not username:
        return None
    # Remove all non-alphanumeric characters and convert to lowercase
    return re.sub(r"[^a-z0-9]", "", username.lower())


def rule(event):
    # Event ID 4688: Windows Security Audit - new process created
    # Event ID 1: Sysmon - process creation
    event_id = event.get("EventID", "")

    if event_id not in ["4688", "1"]:
        return False

    extra_data = event.get("ExtraEventData", {})

    # Event 4688 uses NewProcessName, Sysmon uses Image
    process_name = extra_data.get("NewProcessName", "") or extra_data.get("Image", "")

    if not process_name:
        return False

    # Extract just the filename from the full path
    # Handle both backslash and forward slash separators, and UNC paths
    process_filename = process_name.lower().replace("/", "\\").split("\\")[-1]

    return process_filename in CREDENTIAL_DUMPING_TOOLS


def title(event):
    extra_data = event.get("ExtraEventData", {})
    process_name = extra_data.get("NewProcessName", "") or extra_data.get("Image", "")
    if process_name:
        process_filename = process_name.lower().replace("/", "\\").split("\\")[-1]
    else:
        process_filename = "<UNKNOWN>"

    computer = event.get("Computer", "<UNKNOWN_HOST>")

    # Try to extract username from process path (e.g., C:\Users\jdoe\...)
    username = "<UNKNOWN_USER>"
    if process_name:
        # Normalize path separators for consistent parsing
        normalized_path = process_name.replace("/", "\\")
        parts = normalized_path.split("\\")
        parts_lower = [p.lower() for p in parts]

        # Check for standard Windows user profile path
        if "users" in parts_lower:
            try:
                users_index = parts_lower.index("users")
                if users_index + 1 < len(parts) and parts[users_index + 1]:
                    username = parts[users_index + 1]
            except (ValueError, IndexError):
                pass

        # Fall back to SID if username not extracted from path
        if username == "<UNKNOWN_USER>":
            username = event.get("UserID", "<UNKNOWN_USER>")

    return (
        f"Windows: Credential dumping tool [{process_filename}] "
        f"executed on [{computer}] by [{username}]"
    )


def alert_context(event):
    extra_data = event.get("ExtraEventData", {})
    process_name = extra_data.get("NewProcessName", "") or extra_data.get("Image", "")

    # Extract username from process path or fall back to SID
    username = None
    if process_name:
        # Normalize path separators for consistent parsing
        normalized_path = process_name.replace("/", "\\")
        parts = normalized_path.split("\\")
        parts_lower = [p.lower() for p in parts]

        # Check for standard Windows user profile path
        if "users" in parts_lower:
            try:
                users_index = parts_lower.index("users")
                if users_index + 1 < len(parts) and parts[users_index + 1]:
                    username = parts[users_index + 1]
            except (ValueError, IndexError):
                pass

    return {
        "computer": event.get("Computer"),
        "user": username,
        "username_normalized": normalize_username(username),
        "user_sid": event.get("UserID"),
        "process_name": process_name,
        "command_line": (extra_data.get("CommandLine") or extra_data.get("ProcessCommandLine")),
        "parent_process": (extra_data.get("ParentProcessName") or extra_data.get("ParentImage")),
        "process_id": (extra_data.get("NewProcessId") or extra_data.get("ProcessId")),
        "event_id": event.get("EventID"),
        "description": (
            "Detected execution of credential dumping tool commonly used to "
            "extract OAuth tokens, passwords, and authentication secrets from "
            "Windows memory and registry"
        ),
    }
