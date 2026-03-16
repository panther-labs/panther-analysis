from panther_auth0_helpers import auth0_alert_context


def rule(event):
    data_type = event.deep_get("data", "type", default="<NO_TYPE_FOUND>")
    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    phone_number = str(
        event.deep_get(
            "data", "details", "authenticator", "phone_number", default="<NO_PHONE_NUMBER_FOUND>"
        )
    )

    return (
        data_type == "gd_enrollment_complete"
        and data_description == "Guardian - Enrollment complete (sms)"
        and bool(phone_number)
    )


def unique(event):
    return event.deep_get("data", "user_id", default="")


def dedup(event):
    return str(
        event.deep_get(
            "data", "details", "authenticator", "phone_number", default="<NO_PHONE_NUMBER_FOUND>"
        )
    )


def title(event):
    user_id = event.deep_get("data", "user_id", default="<NO_USER_ID_FOUND>")
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    phone_number = event.deep_get(
        "data", "details", "authenticator", "phone_number", default="<NO_PHONE_NUMBER_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] having user_id [{user_id}] "
        f"shares phone number [{phone_number}] as MFA in "
        f"your organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
