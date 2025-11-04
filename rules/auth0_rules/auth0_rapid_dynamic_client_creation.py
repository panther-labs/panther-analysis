from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")

    return all(
        [
            is_auth0_config_event(event),
            data_type == "sapi",
            data_description == "Dynamic client registration",
        ]
    )


def title(event):

    client_id = event.deep_get(
        "data", "details", "response", "body", "client_id", default="<NO_CLIENT_ID_FOUND"
    )
    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")

    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 Significant number of Dynamic Client registration of [{data_description}] "
        f"with client id [{client_id}] in "
        f"your organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
