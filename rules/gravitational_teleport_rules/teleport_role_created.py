def rule(event):
    return event.get("event") == "role.created"


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] created Role "
        f"[{event.get('name', '<UNKNOWN_NAME>')}] "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
