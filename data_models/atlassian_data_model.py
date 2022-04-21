import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get

audit_log_type_map = {
    "user_login": event_type.SUCCESSFUL_LOGIN,
    "user_logout": event_type.SUCCESSFUL_LOGOUT,
    "user_created": event_type.USER_ACCOUNT_CREATED,
    "twosv_disabled_for_user": event_type.MFA_DISABLED,
    "group_created": event_type.USER_GROUP_CREATED,
    "group_deleted": event_type.USER_GROUP_DELETED,
    "user_granted_role": event_type.USER_ROLE_MODIFIED,
    "user_revoked_role": event_type.USER_ROLE_DELETED,
}


def get_event_type(event):
    audit_log_type = deep_get(event, "AuditLog", "Type")
    matched = audit_log_type_map.get(audit_log_type)
    if matched is not None:
        return matched

    if audit_log_type in ("added_org_admin", "group_granted_admin_access"):
        return event_type.ADMIN_ROLE_ASSIGNED

    return None
