from panther_duo_helpers import deserialize_administrator_log_event_description, duo_alert_context


def rule(event):
    if event.get("action") == "admin_single_sign_on_update":
        description = deserialize_administrator_log_event_description(event)
        enforcement_status = description.get("enforcement_status", "required")
        return enforcement_status != "required"
    return False


def title(event):
    description = deserialize_administrator_log_event_description(event)
    return (
        f"Duo: [{event.get('username', '<username_not_found>')}] "
        "changed SAML authentication requirements for Administrators "
        f"to [{description.get('enforcement_status', '<enforcement_status_not_found>')}]"
    )


def alert_context(event):
    return duo_alert_context(event)
