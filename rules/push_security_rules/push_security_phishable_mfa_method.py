from panther_base_helpers import deep_get

identity_providers = ("MICROSOFT_365", "GOOGLE_WORKSPACE", "OKTA", "JUMPCLOUD", "PING")

phishable_mfa = ("EMAIL_OTP", "PHONE_CALL", "SMS", "APP_PASSWORD")


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    mfa_methods = deep_get(event, "new", "mfaMethods")

    for method in mfa_methods:
        if method in phishable_mfa:
            return True

    return False


def severity(event):
    if deep_get(event, "new", "appType") in identity_providers:
        return "HIGH"
    return "INFO"


def title(event):
    mfa_methods = ", ".join(deep_get(event, "new", "mfaMethods", default="No MFA"))

    return f"{deep_get(event, 'new', 'email')} using phisbable MFA method with {deep_get(event, 'new', 'appType', default=[])}. MFA methods enabled: {mfa_methods}"
