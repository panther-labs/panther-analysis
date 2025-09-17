def rule(event):
    return event.get("event") == "lock.created"


def title(event):
    return (
        f"Teleport Alert: Lock created by {event.get('updated_by', '<UNKNOWN_UPDATED_BY>')} "
        f"to lock out user {event.get('target', {}).get('user', '<UNKNOWN_USER>')} "
        f"on cluster [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
