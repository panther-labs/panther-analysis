from panther_crowdstrike_event_streams_helpers import audit_keys_dict, cs_alert_context


def rule(event):
    # Return True if allowlist is deleted
    if event.deep_get("event", "OperationName") == "DeleteAllowlistGroup":
        return True

    # Return True if allowlist is disabled
    if event.deep_get("event", "OperationName") == "UpdateAllowlistGroup":
        audit_keys = audit_keys_dict(event)
        return audit_keys.get("active") == "false" and audit_keys.get("old_active") == "true"

    return False


def title(event):
    actor = event.deep_get("event", "UserId")
    audit_keys = audit_keys_dict(event)
    list_name = audit_keys.get("group_name", "UNKNOWN_GROUP")

    verb = {"DeleteAllowlistGroup": "deleted", "UpdateAllowlistGroup": "disabled"}.get(
        event.deep_get("event", "OperationName"), "removed"
    )

    return f'{actor} {verb} IP allowlist "{list_name}"'


def dedup(event):
    # We wanna group alerts if a user disables, then deletes the same allowlist
    actor = event.deep_get("event", "UserId")
    audit_keys = audit_keys_dict(event)
    list_name = audit_keys.get("group_name", "UNKNOWN_GROUP")
    return f"{actor}-{list_name}"


def alert_context(event):
    return cs_alert_context(event)


def severity(event):
    # Downgrade severity if a disabled allowlist was deleted
    if all(
        [
            event.deep_get("event", "OperationName") == "DeleteAllowlistGroup",
            audit_keys_dict(event).get("enabled") == "false",
        ]
    ):
        return "INFO"
    return "DEFAULT"
