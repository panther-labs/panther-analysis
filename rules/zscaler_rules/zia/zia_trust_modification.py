from panther_zscaler_helpers import zia_alert_context, zia_success


def rule(event):
    if not zia_success(event):
        return False
    action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
    category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
    saml_enabled_pre = event.deep_get("event", "preaction", "samlEnabled", default="")
    saml_enabled_post = event.deep_get("event", "postaction", "samlEnabled", default="")
    # Only alert if both fields are present and have different values
    if (
        action == "UPDATE"
        and category == "ADMINISTRATOR_MANAGEMENT"
        and saml_enabled_pre != ""
        and saml_enabled_post != ""
        and saml_enabled_pre != saml_enabled_post
    ):
        return True
    return False


def title(event):
    return (
        f"[Zscaler.ZIA]: SAML configuration was changed by admin with id "
        f"[{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"
    )


def alert_context(event):
    return zia_alert_context(event)
