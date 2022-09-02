SCAN_COMMANDS = {"arp", "arp-scan", "fping", "nmap"}


def rule(event):
    # Filter out commands
    if event.get("event") == "session.command" and not event.get("argv"):
        return False
    # Check that the program is in our watch list
    return event.get("program") in SCAN_COMMANDS


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] has issued a network scan with "
        f"[{event.get('program', '<UNKNOWN_PROGRAM>')}]"
    )
