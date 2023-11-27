def rule(event):
    # Filter the events
    if event.get("event") != "session.command":
        return False
    # Ignore list/read events
    if "-l" in event.get("argv", []):
        return False
    return event.get("program") == "crontab"


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] has modified scheduled jobs"
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
