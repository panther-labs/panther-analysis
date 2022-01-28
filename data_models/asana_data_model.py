import panther_event_type_helpers as event_type


def get_event_type(event):
    audit_log_type_map = {
        "user_login_succeeded": event_type.SUCCESSFUL_LOGIN,
        "user_login_failed": event_type.FAILED_LOGIN,
        "user_invited": event_type.USER_ACCOUNT_CREATED,
        "user_reprovisioned": event_type.USER_ACCOUNT_CREATED,
        "user_deprovisioned": event_type.USER_ACCOUNT_DELETED,
        "user_workspace_admin_role_changed": event_type.ADMIN_ROLE_ASSIGNED,
    }
    logged_event_type = event.get("event_type")
    # Since this is a safe dict get if the event type is not mapped
    # there is an implicit return of None
    return audit_log_type_map.get(logged_event_type)
