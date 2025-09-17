SCAN_COMMANDS = {"arp", "arp-scan", "fping", "nmap"}


def rule(event):
    # Filter out commands
    if event.get("event") == "session.command" and not event.get("argv"):
        return False
    # Check that the program is in our watch list
    return event.get("program") in SCAN_COMMANDS


def title(event):
    return (
        f"Teleport Alert: Network scan detected from user [{event.get('user', '<UNKNOWN_USER>')}] "
        f"using [{event.get('program', '<UNKNOWN_PROGRAM>')}] "
        f"on cluster [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
