SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def upwind_severity(event) -> str:
    """Map Upwind severity string to a Panther severity level.

    Returns DEFAULT for any value outside the known set so the alert
    still fires but is flagged for review rather than silently dropped.
    """
    raw = event.get("severity", "")
    if not isinstance(raw, str):
        return "DEFAULT"
    return SEVERITY_MAP.get(raw.upper(), "DEFAULT")


def upwind_is_known_severity(event) -> bool:
    """Return True only when the event carries a recognised severity value."""
    return upwind_severity(event) != "DEFAULT"


def upwind_format_mitre_attacks(event) -> list:
    """Return a list of simplified MITRE ATT&CK dicts from the event."""
    return [
        {
            "tactic": m.get("tactic_name"),
            "technique_id": m.get("technique_id"),
            "technique": m.get("technique_name"),
        }
        for m in event.get("mitre_attacks", [])
    ]


def upwind_format_resource(event) -> dict:
    """Return a normalised resource dict from the event."""
    resource = event.get("resource", {})
    return {
        "name": resource.get("name"),
        "type": resource.get("type"),
        "namespace": resource.get("namespace"),
        "region": resource.get("region"),
        "cloud_provider": resource.get("cloud_provider"),
        "cloud_account_id": resource.get("cloud_account_id"),
        "cloud_account_name": resource.get("cloud_account_name"),
        "risk_categories": resource.get("risk_categories", []),
        "internet_facing": event.deep_walk(
            "resource", "internet_exposure", "ingress", "active_communication", default=None
        ),
    }


def upwind_format_initiators(event) -> list:
    """Return a list of initiator dicts extracted from trigger events."""
    initiators = []
    for trigger in event.get("triggers", []):
        for evt in trigger.get("events", []):
            initiator = evt.get("initiator")
            if initiator:
                initiators.append(
                    {
                        "name": initiator.get("name"),
                        "type": initiator.get("type"),
                        "arn": initiator.get("arn"),
                        "user_name": initiator.get("userName"),
                        "account_id": initiator.get("accountId"),
                    }
                )
    return initiators


def upwind_triggered_policies(event) -> list:
    """Return a list of policy names from the triggers array."""
    return [t.get("policy_name") for t in event.get("triggers", []) if t.get("policy_name")]


def upwind_commands_observed(event) -> list:
    """Return a list of commands observed across all trigger events."""
    commands = []
    for trigger in event.get("triggers", []):
        for evt in trigger.get("events", []):
            if cmd := evt.get("data", {}).get("command"):
                commands.append(cmd)
    return commands


def upwind_base_alert_context(event) -> dict:
    """Return the common alert context fields shared across all Upwind rules."""
    return {
        "detection_id": event.get("id"),
        "category": event.get("category"),
        "type": event.get("type"),
        "status": event.get("status"),
        "occurrence_count": event.get("occurrence_count"),
        "resource": upwind_format_resource(event),
    }
