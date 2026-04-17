SUSPICIOUS_COMMANDS = {"nc", "wget"}


def rule(event):
    if event.get("event") != "session.command":
        return False
    # Ignore commands without arguments
    if not event.get("argv"):
        return False
    return event.get("program") in SUSPICIOUS_COMMANDS


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] has executed the command "
        f"[{event.get('program', '<UNKNOWN_PROGRAM>')}] "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
