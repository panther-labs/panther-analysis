from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("name") == "pack_incident-response_listening_ports"
        and deep_get(event, "columns", "port") == "22"
        and event.get("action") == "added"
    )
