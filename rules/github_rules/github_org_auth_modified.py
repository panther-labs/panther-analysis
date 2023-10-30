from global_filter_github import filter_include_event

AUTH_CHANGE_EVENTS = [
    "org.saml_disabled",
    "org.saml_enabled",
    "org.disable_two_factor_requirement",
    "org.enable_two_factor_requirement",
    "org.update_saml_provider_settings",
    "org.enable_oauth_app_restrictions",
    "org.disable_oauth_app_restrictions",
]


def rule(event):
    if not filter_include_event(event):
        return False

    if not event.get("action").startswith("org."):
        return False

    return event.get("action") in AUTH_CHANGE_EVENTS


def title(event):
    return f"GitHub auth configuration was changed by {event.get('actor', '<UNKNOWN USER>')}"
