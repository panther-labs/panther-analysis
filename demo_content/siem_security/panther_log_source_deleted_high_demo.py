from typing import Any, Dict


def rule(event: Dict[str, Any]) -> bool:
    return (
        event.get("actionName") == "DELETE_LOG_SOURCE" and event.get("actionResult") == "SUCCEEDED"
    )


def title(event: Dict[str, Any]) -> str:
    actor = event.get("actor", {}).get("name", event.get("actor", {}).get("id", "unknown"))
    return f"Log Source Deleted in Panther by [{actor}]"
