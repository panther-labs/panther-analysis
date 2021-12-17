def rule(event):
    auth_change_events = [
        "org.saml_disabled",
        "org.saml_enabled",
        "org.disable_two_factor_requirement",
        "org.enable_two_factor_requirement",
        "org.update_saml_provider_settings",
        "org.enable_oauth_app_restrictions",
        "org.disable_oauth_app_restrictions",
    ]

    if not event.get("action").startswith("org."):
        return False

    return event.get("action") in auth_change_events


def title(event):
    return f"GitHub auth configuration was changed by {event.get('actor', '<UNKNOWN USER>')}"
