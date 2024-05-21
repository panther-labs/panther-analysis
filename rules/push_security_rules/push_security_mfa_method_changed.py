from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("old") is None:
        return False

    new_mfa_methods = set(deep_get(event, "new", "mfaMethods"))
    old_mfa_methods = set(deep_get(event, "old", "mfaMethods", default=[]))

    if new_mfa_methods != old_mfa_methods:
        return True

    return False


def severity(event):
    if deep_get(event, "new", "mfaMethods") == []:
        return "HIGH"
    return "LOW"


def title(event):
    mfa_methods = ", ".join(deep_get(event, "new", "mfaMethods", default="No MFA"))
    new_email = deep_get(event, "new", "email")
    new_apptype = deep_get(event, "new", "appType")

    if mfa_methods == "":
        return f"{new_email} removed all MFA methods on {new_apptype}"
    return f"{new_email} changed MFA method to {mfa_methods} on {new_apptype}"
