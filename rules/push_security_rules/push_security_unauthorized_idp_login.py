# Configure allowed identity provider logins to SaaS apps
allowed_idps = {
    "GOOGLE_WORKSPACE": {"OIDC_LOGIN", "SAML_LOGIN"},
    "OKTA": {"PASSWORD_LOGIN"},
    None: {"PASSWORD_LOGIN"},
}


def rule(event):
    if event.get("object") != "LOGIN":
        return False

    identity_provider = event.deep_get("new", "identityProvider")
    login_type = event.deep_get("new", "loginType")

    if identity_provider in allowed_idps and login_type in allowed_idps[identity_provider]:
        return False

    return True


def title(event):
    identity_provider = event.deep_get("new", "identityProvider", default="Null identityProvider")
    login_type = event.deep_get("new", "loginType", default="Null loginType")
    app_type = event.deep_get("new", "appType", default="Null appType")
    new_email = event.deep_get("new", "email")

    return f"Unauthorized identity provider in use. User: {new_email} \
        used {identity_provider} {login_type} on {app_type}"
