from panther_databricks_helpers import databricks_alert_context, is_login_action


def rule(event):
    if not is_login_action(event):
        return False

    if event.deep_get("response", "statusCode") != 200:
        return False

    # Alert on logins that bypass SSO (SAML).
    # If authentication_method is missing, fall back to checking the action name.
    auth_method = event.deep_get("requestParams", "authentication_method", default="")
    if auth_method:
        return auth_method != "BROWSER_BYO_IDP_SAML"

    # No auth_method field: treat non-SAML login actions as non-SSO
    return event.get("actionName") not in ("samlLogin",)


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    auth_method = event.deep_get("requestParams", "authentication_method", default="Unknown")
    action = event.get("actionName", "login")
    return f"Non-SSO login by {user} via {auth_method} ({action})"


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"non_sso_login_{user}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "authentication_method": event.deep_get("requestParams", "authentication_method"),
        },
    )
