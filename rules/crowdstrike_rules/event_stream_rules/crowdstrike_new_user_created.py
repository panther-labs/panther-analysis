from panther_base_helpers import key_value_list_to_dict
from panther_crowdstrike_event_streams_helpers import cs_alert_context


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
    context = cs_alert_context(event)
    actor = context.get("actor_user", "UNKNOWN_ACTOR")
    target = context.get("target_name", "UNKNOWN_TARGET")
    context["actor_target"] = f"{actor}-{target}"
    return context
