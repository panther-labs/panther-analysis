def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("old") is None:
        return False

    new_mfa_methods = set(event.deep_get("new", "mfaMethods"))
    old_mfa_methods = set(event.deep_get("old", "mfaMethods", default=[]))

    if new_mfa_methods != old_mfa_methods:
        return True

    return False


def severity(event):
    if event.deep_get("new", "mfaMethods") == []:
        return "HIGH"
    return "LOW"


def title(event):
    mfa_methods = ", ".join(event.deep_get("new", "mfaMethods", default="No MFA"))
    new_email = event.deep_get("new", "email")
    new_apptype = event.deep_get("new", "appType")

    if mfa_methods == "":
        return f"{new_email} removed all MFA methods on {new_apptype}"
    return f"{new_email} changed MFA method to {mfa_methods} on {new_apptype}"
