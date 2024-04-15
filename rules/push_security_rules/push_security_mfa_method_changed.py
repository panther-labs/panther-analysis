from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("old") == None:
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

    if mfa_methods == "":
        return f"{deep_get(event, 'new', 'email')} removed all MFA methods on {deep_get(event, 'new', 'appType')}"
    return f"{deep_get(event, 'new', 'email')} changed MFA method to {mfa_methods} on {deep_get(event, 'new', 'appType')}"
