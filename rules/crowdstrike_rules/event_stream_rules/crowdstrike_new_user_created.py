from crowdstrike_event_streams_helpers import cs_alert_context
from panther_base_helpers import key_value_list_to_dict


def rule(event):
    return all(
        [
            event.deep_get("event", "OperationName") == "createUser",
            event.deep_get("event", "Success"),
        ]
    )


def title(event):
    audit_keys = key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues"), "Key", "ValueString"
    )

    actor = event.deep_get("event", "UserId", "UNKNOWN USER")
    target = audit_keys.get("target_name")

    return f"[{actor}] created a new user: [{target}]"


def alert_context(event):
    return cs_alert_context(event)
