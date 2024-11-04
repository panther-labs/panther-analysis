MFA_EXCEPTIONS = {"PANTHER_READONLY", "PANTHER_ADMIN", "PANTHERACCOUNTADMIN"}


def rule(event):
    return all(
        (
            event.get("EVENT_TYPE") == "LOGIN",
            event.get("IS_SUCCESS") == "YES",
            event.get("FIRST_AUTHENTICATION_FACTOR") == "PASSWORD",
            not event.get("SECOND_AUTHENTICATION_FACTOR"),
            event.get("USER_NAME") not in MFA_EXCEPTIONS,
        )
    )


def title(event):
    source = event.get("p_source_label", "<UNKNOWN SOURCE>")
    user = event.get("USER_NAME", "<UNKNOWN USER>")
    return f"{source}: User {user} logged in without MFA"
