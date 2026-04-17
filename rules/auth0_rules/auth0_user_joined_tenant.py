from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    scopes = event.deep_get(
        "data",
        "details",
        "request",
        "auth",
        "credentials",
        "scopes",
        default=["<NO_CREDENTIAL_SCOPE>"],
    )
    state = event.deep_get("data", "details", "request", "body", "state", default="<NO_STATE>")
    return all(
        [
            data_description == "Update an invitation",
            "update:tenant_invitations" in scopes,
            state == "accepted",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] has accepted an invitation to join your "
        f"organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
