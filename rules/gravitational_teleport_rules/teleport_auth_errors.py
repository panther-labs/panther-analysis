def rule(event):
    return bool(event.get("error")) and event.get("event") == "auth"


def title(event):
    return (
        f"Teleport Alert: High volume of SSH errors detected from user "
        f"[{event.get('user', '<UNKNOWN_USER>')}] "
        f"on cluster [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
