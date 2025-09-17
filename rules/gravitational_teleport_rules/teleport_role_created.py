def rule(event):
    return event.get("event") == "role.created"


def title(event):
    return (
        f"Teleport Alert: New Role [{event.get('name', '<UNKNOWN_NAME>')}] created "
        f"by user [{event.get('user', '<UNKNOWN_USER>')}] "
        f"on cluster [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
