from panther_base_helpers import pattern_match_list
from panther_base_helpers import deep_get

USER_CREATE_PATTERNS = [
    "wget",  # user password expiry
    "curl",  # change passwords for users
]


def rule(event):
    # Filter the events

    if event.get("event_type", {}) != "session.command":
        return False
    # Check that the program matches our list above
    if (
        event.get("event_data", {}).get("program") == "wget"
        or event.get("event_data", {}).get("program") == "curl"
    ):
        return True
    else:
        return False


def title(event):
    return (
        event.get("user")
        + " has run Illegal command run to download file outside of network = "
        + event.deep_get("event_data", "program")
    )


def alert_context(event):
    alert = {
        "user": event.get("user"),
        "event": event.get("event_data", {}).get("event"),
        "command": event.get("event_data", {}).get("program"),
        "cluster": event.get("event_data", {}).get("cluster_name"),
    }
    return alert
