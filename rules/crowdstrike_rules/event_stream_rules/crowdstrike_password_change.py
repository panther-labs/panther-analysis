from crowdstrike_event_streams_helpers import cs_alert_context
from panther_base_helpers import key_value_list_to_dict


def rule(event):
    # Return True if this is a password change event
    subevent = event.get("event", {})
    return subevent.get("OperationName") == "changePassword" and subevent.get("Success")


def title(event):
    audit_keys = key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues"), "Key", "ValueString"
    )
    target = audit_keys.get("target_name", "UNKNOWN USER")
    actor = event.deep_get("event", "UserId")

    if target == actor:
        return f"[{actor}] changed their password."

    return f"[{actor}] changed the password of [{target}]"


def alert_context(event):
    return cs_alert_context(event)
