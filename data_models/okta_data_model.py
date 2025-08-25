import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get


def get_event_type(event):
    # pylint: disable=too-many-return-statements, too-many-branches, too-complex
    event_type_name = event.get("eventType", "")
    outcome = event.get("outcome", {}).get("result", "")

    # Authentication Events
    if event_type_name == "user.session.start":
        if outcome == "FAILURE":
            return event_type.FAILED_LOGIN
        if outcome == "SUCCESS":
            return event_type.SUCCESSFUL_LOGIN

    if event_type_name == "user.session.end":
        return event_type.SUCCESSFUL_LOGOUT

    # MFA Events
    if event_type_name in ["user.mfa.factor.deactivate", "user.mfa.factor.suspend"]:
        if event.get("outcome", {}).get("reason", "").startswith("User reset"):
            return event_type.MFA_RESET
        return event_type.MFA_DISABLED

    if event_type_name in [
        "user.mfa.factor.activate",
        "user.mfa.factor.unsuspend",
        "user.mfa.factor.update",
    ]:
        return event_type.MFA_ENABLED

    if event_type_name == "system.mfa.factor.deactivate":
        return event_type.ADMIN_MFA_DISABLED

    # User Lifecycle Events
    if event_type_name == "user.lifecycle.create":
        return event_type.USER_ACCOUNT_CREATED
    if event_type_name == "user.lifecycle.deactivate":
        return event_type.USER_ACCOUNT_DELETED
    if event_type_name in [
        "user.lifecycle.suspend",
        "user.lifecycle.activate",
        "user.lifecycle.unsuspend",
    ]:
        return event_type.USER_ACCOUNT_MODIFIED

    # Permission Events (group membership, application access)
    if event_type_name in ["group.user_membership.add", "application.user_membership.add"]:
        return event_type.PERMISSION_GRANTED
    if event_type_name in ["group.user_membership.remove", "application.user_membership.remove"]:
        return event_type.PERMISSION_REVOKED

    # Security Configuration Events (policies, applications, security settings)
    if event_type_name in [
        "policy.lifecycle.create",
        "policy.lifecycle.update",
        "policy.lifecycle.delete",
        "policy.lifecycle.activate",
        "policy.lifecycle.deactivate",
        "policy.rule.add",
        "policy.rule.update",
        "policy.rule.delete",
        "policy.rule.activate",
        "policy.rule.deactivate",
        "application.lifecycle.create",
        "application.lifecycle.update",
        "application.lifecycle.delete",
        "application.lifecycle.activate",
        "application.lifecycle.deactivate",
    ]:
        return event_type.SECURITY_CONFIG_CHANGED

    return None


def get_actor_user(event):
    actor = deep_get(event, "actor", "displayName", default="unknown")
    if actor == "unknown":
        actor = deep_get(event, "actor", "alternateId", default="Unknown User")
    return actor
