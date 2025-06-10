from typing import Any, Dict


def rule(event: Dict[str, Any]) -> bool:
    return (
        event.get("actionName") == "DELETE_LOG_SOURCE" and event.get("actionResult") == "SUCCEEDED"
    )


def title(event: Dict[str, Any]) -> str:
    actor = event.get("actor", {}).get("name", event.get("actor", {}).get("id", "unknown"))
    return f"Log Source Deleted in Panther by [{actor}]"


def runbook(event: Dict[str, Any]) -> str:
    actor = event.get("actor", {}).get("name", event.get("actor", {}).get("id", "unknown"))
    source_ip = event.get("sourceIP", "unknown")
    timestamp = event.get("timestamp", event.get("p_event_time", "unknown"))
    return f"""
1. Review the Panther Audit logs for additional actions by [{actor}] around [{timestamp}] from IP [{source_ip}].
2. Confirm if the log source deletion was authorized and expected.
3. If unauthorized, investigate for potential misconfiguration or malicious activity.
4. Restore the deleted log source if necessary to maintain visibility.
"""
