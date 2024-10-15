def rule(event):
    return (
        event.get("name") == "pack_incident-response_listening_ports"
        and event.deep_get("columns", "port") == "22"
        and event.get("action") == "added"
    )
