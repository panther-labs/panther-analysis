MFA_EXCEPTIONS = {"PANTHER_READONLY", "PANTHER_ADMIN", "PANTHERACCOUNTADMIN"}


def rule(event):
    return event.get("user_name", "") not in MFA_EXCEPTIONS
