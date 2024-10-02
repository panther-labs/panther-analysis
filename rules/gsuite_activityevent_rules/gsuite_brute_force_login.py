def rule(event):
    # Filter login events
    if event.get("type") != "login":
        return False

    # Pattern match this event to the recon actions
    return bool(event.get("name") == "login_failure")


def title(event):
    return (
        f"Brute force login suspected for user "
        f"[{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
