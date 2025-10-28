import json

from panther_auth0_helpers import auth0_alert_context
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "Auth0.SamePhone.MultipleUsers.MFA"


def rule(event):

    data_type = event.deep_get("data", "type", default="<NO_TYPE_FOUND>")
    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    user_id = event.deep_get("data", "user_id", default="<NO_USER_ID_FOUND>")

    phone_number = str(
        event.deep_get(
            "data", "details", "authenticator", "phone_number", default="<NO_PHONE_NUMBER_FOUND>"
        )
    )

    if (
        data_type != "gd_enrollment_complete"
        or data_description != "Guardian - Enrollment complete (sms)"
        or not phone_number
    ):
        return False

    key = phone_number + "-" + RULE_ID
    user_set = add_to_string_set(key, [user_id])

    if isinstance(user_set, str):
        # This is a unit test
        user_set = json.loads(user_set) if user_set else []

    return len(user_set) > 1


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
