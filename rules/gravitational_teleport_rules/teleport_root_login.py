def rule(event):
    return event.get("event") == "session.start" and event.get("login") == "root"


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('server_hostname', '<UNKNOWN_HOSTNAME>')}] as root "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
