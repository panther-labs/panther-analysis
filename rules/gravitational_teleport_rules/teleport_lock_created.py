def rule(event):
    return event.get("event") == "lock.created"


def title(event):
    return (
        f"A Teleport Lock was created by {event.get('updated_by', '<UNKNOWN_UPDATED_BY>')} "
        f"to Lock out user {event.get('target', {}).get('user', '<UNKNOWN_USER>')} "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
