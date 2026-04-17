from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    important_event_types = {
        "FEDERATION_SETTINGS_CREATED",
        "FEDERATION_SETTINGS_DELETED",
        "FEDERATION_SETTINGS_UPDATED",
        "IDENTITY_PROVIDER_CREATED",
        "IDENTITY_PROVIDER_UPDATED",
        "IDENTITY_PROVIDER_DELETED",
        "IDENTITY_PROVIDER_ACTIVATED",
        "IDENTITY_PROVIDER_DEACTIVATED",
        "IDENTITY_PROVIDER_JWKS_REVOKED",
        "OIDC_IDENTITY_PROVIDER_UPDATED",
        "OIDC_IDENTITY_PROVIDER_ENABLED",
        "OIDC_IDENTITY_PROVIDER_DISABLED",
    }
    return event.get("eventTypeName") in important_event_types


def title(event):
    target_username = event.get("targetUsername", "<USER_NOT_FOUND>")
    org_id = event.get("orgId", "<ORG_NOT_FOUND>")

    return f"MongoDB Atlas: User [{target_username}] roles changed in org [{org_id}]"


def alert_context(event):
    return mongodb_alert_context(event)
