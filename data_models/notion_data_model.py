import panther_event_type_helpers as event_type


def get_event_type(event):
    # pylint: disable=too-many-return-statements
    return {
        'user.login': event_type.SUCCESSFUL_LOGIN,
        'user.logout': event_type.SUCCESSFUL_LOGOUT,
        'user.settings.email_updated': event_type.USER_ACCOUNT_MODIFIED,
        'user.settings.login_method.mfa_backup_code_updated': event_type.MFA_RESET,
        'user.settings.login_method.mfa_totp_updated': event_type.MFA_RESET,
        'user.settings.login_method.password_added': event_type.USER_ACCOUNT_MODIFIED,
        'user.settings.preferred_name_updated': event_type.USER_ACCOUNT_MODIFIED,
        'user.settings.profile_photo_updated': event_type.USER_ACCOUNT_MODIFIED,
        'workspace.permissions.member_role_updated': event_type.USER_ROLE_MODIFIED
    }.get(event.deep_get("event", "type"))


def get_actor_user(event):
    actor = event.deep_get("event", "actor", "id", default="UNKNOWN USER")
    if event.deep_get("event", "actor", "person"):
        actor = event.deep_get("event", "actor", "person", "email", default="UNKNOWN USER")
    return actor
