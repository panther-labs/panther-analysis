from crowdstrike_event_streams_helpers import cs_alert_context
from panther_base_helpers import key_value_list_to_dict


def rule(event):
    return all(
        [
            event.deep_get("event", "OperationName") == "changePassword",
            event.deep_get("event", "Success"),
        ]
    )


def title(event):
    audit_keys = key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues"), "Key", "ValueString"
    )
    target = audit_keys.get("target_name", "UNKNOWN USER")
    actor = event.deep_get("event", "UserId")

    if target == actor:
        return f"[{actor}] changed their password."

    return f"[{actor}] changed the password of [{target}]"


def severity(event):
    # Downgrade sev if password changed by same uer

    audit_keys = key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues"), "Key", "ValueString"
    )
    target = audit_keys.get("target_name", "UNKNOWN USER")
    actor = event.deep_get("event", "UserId")

    if target == actor:
        return "INFO"

    return "DEFAULT"


def alert_context(event):
    return cs_alert_context(event)
