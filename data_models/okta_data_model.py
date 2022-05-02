import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get


def get_event_type(event):
    if (
        event.get("eventType") == "user.session.start"
        and event.get("outcome", {}).get("result") == "FAILURE"
    ):
        return event_type.FAILED_LOGIN
    if (
        event.get("eventType") == "user.session.start"
        and event.get("outcome", {}).get("result") == "SUCCESS"
    ):
        return event_type.SUCCESSFUL_LOGIN
    if event.get("eventType") in ["user.mfa.factor.deactivate", "user.mfa.factor.suspend"]:
        return event_type.MFA_DISABLED

    if event.get("eventType") in [
        "user.mfa.factor.activate",
        "user.mfa.factor.unsuspend",
        "user.mfa.factor.update ",
    ]:
        return event_type.MFA_ENABLED

    if event.get("eventType") == "system.mfa.factor.deactivate":
        return event_type.ADMIN_MFA_DISABLED
    return None


def get_actor_user(event):
    actor = deep_get(event, "actor", "displayName", default="unknown")
    if actor == "unknown":
        actor = deep_get(event, "actor", "alternateId", default="Unknown User")
    return actor
