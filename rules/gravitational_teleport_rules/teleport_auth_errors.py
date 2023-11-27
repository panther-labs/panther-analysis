def rule(event):
    return bool(event.get("error")) and event.get("event") == "auth"


def title(event):
    return (
        f"A high volume of SSH errors was detected from user "
        f"[{event.get('user', '<UNKNOWN_USER>')}] "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
