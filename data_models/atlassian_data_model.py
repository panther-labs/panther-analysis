import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get


def get_event_type(event): # pylint: disable=too-many-return-statements,
    if deep_get(event, "AuditLog", "Type") == "user_login":
        return event_type.SUCCESSFUL_LOGIN

    if deep_get(event, "AuditLog", "Type") == "user_logout":
        return event_type.SUCCESSFUL_LOGOUT

    if deep_get(event, "AuditLog", "Type") == "user_created":
        return event_type.USER_ACCOUNT_CREATED

    if deep_get(event, "AuditLog", "Type") in ("added_org_admin", "group_granted_admin_access"):
        return event_type.ADMIN_ROLE_ASSIGNED

    if deep_get(event, "AuditLog", "Type") == "twosv_disabled_for_user":
        return event_type.MFA_DISABLED

    if deep_get(event, "AuditLog", "Type") == "twosv_disabled_for_user":
        return event_type.MFA_DISABLED

    if deep_get(event, "AuditLog", "Type") == "group_created":
        return event_type.USER_GROUP_CREATED

    if deep_get(event, "AuditLog", "Type") == "group_deleted":
        return event_type.USER_GROUP_DELETED

    if deep_get(event, "AuditLog", "Type") == "user_granted_role":
        return event_type.USER_ROLE_MODIFIED

    if deep_get(event, "AuditLog", "Type") == "user_revoked_role":
        return event_type.USER_ROLE_DELETED

    return None
