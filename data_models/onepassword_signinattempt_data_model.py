import panther_event_type_helpers as event_type


def get_event_type(event):
    failed_login_events = ["credentials_failed", "mfa_failed", "modern_version_failed"]

    if event.get("category") == "success":
        return event_type.SUCCESSFUL_LOGIN

    if event.get("category") in failed_login_events:
        return event_type.FAILED_LOGIN

    return None
