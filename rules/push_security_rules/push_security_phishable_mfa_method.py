identity_providers = ("MICROSOFT_365", "GOOGLE_WORKSPACE", "OKTA", "JUMPCLOUD", "PING")

phishable_mfa = ("EMAIL_OTP", "PHONE_CALL", "SMS", "APP_PASSWORD")


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    mfa_methods = event.deep_get("new", "mfaMethods")

    for method in mfa_methods:
        if method in phishable_mfa:
            return True

    return False


def severity(event):
    if event.deep_get("new", "appType") in identity_providers:
        return "HIGH"
    return "INFO"


def title(event):
    mfa_methods = ", ".join(event.deep_get("new", "mfaMethods", default="No MFA"))
    new_email = event.deep_get("new", "email")
    app_type = event.deep_get("new", "appType", default=[])

    return f"{new_email} using phishable MFA method with {app_type}. \
            MFA methods enabled: {mfa_methods}"
