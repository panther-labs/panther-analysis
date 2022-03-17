import ast
import logging

from panther import lookup_aws_account_name
from panther_base_helpers import deep_get
from panther_oss_helpers import check_account_age


def rule(event):
    if event.get("eventName") != "ConsoleLogin":
        return False

    # Extract some nested JSON structure
    additional_event_data = event.get("additionalEventData", {})
    response_elements = event.get("responseElements", {})

    # If using AWS SSOv2 or other SAML provider return False
    if (
        "AWSReservedSSO" in deep_get(event, "userIdentity", "arn")
        or additional_event_data.get("SamlProviderArn") is not None
    ):
        return False

    # If Account is less than 3 days old do not alert
    # This functionality is not enabled by default, in order to start logging new user creations
    # Enable indicator_creation_rules/new_account_logging to start logging new users
    new_user_string = (
        deep_get(event, "userIdentity", "userName", default="<MISSING_USER_NAME>")
        + "-"
        + deep_get(event, "userIdentity", "principalId", default="<MISSING_ID>")
    )
    is_new_user = check_account_age(new_user_string)
    if isinstance(is_new_user, str):
        logging.debug("check_account_age is a mocked string for unit testing")
        is_new_user = ast.literal_eval(is_new_user)
    if is_new_user:
        return False

    is_new_account = check_account_age(event.get("recipientAccountId"))
    if isinstance(is_new_account, str):
        logging.debug("check_account_age is a mocked string for unit testing")
        is_new_account = ast.literal_eval(is_new_account)
    if is_new_account:
        return False

    return (
        response_elements.get("ConsoleLogin") == "Success"
        and additional_event_data.get("MFAUsed") == "No"
    )


def title(event):
    if deep_get(event, "userIdentity", "type") == "Root":
        user_string = "the root user"
    else:
        user_string = f"user {deep_get(event, 'userIdentity', 'userName')}"
    account_id = event.get("recipientAccountId")
    account_name = lookup_aws_account_name(account_id)
    if account_id == account_name:
        account_string = f"unnamed account ({account_id})"
    else:
        account_string = f"{account_name} account ({account_id})"

    return f"AWS login detected without MFA for [{user_string}] in [{account_string}]"
