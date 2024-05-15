import logging

from panther_base_helpers import aws_rule_context
from panther_default import lookup_aws_account_name
from panther_detection_helpers.caching import check_account_age

# Set to True for environments that permit direct role assumption via external IDP
ROLES_VIA_EXTERNAL_IDP = False


# pylint: disable=R0911,R0912,R1260
def rule(event):
    if event.udm("event_name") != "ConsoleLogin":
        return False

    # Extract some nested JSON structure
    user_identity_type = event.udm("user_type", default="")

    # When there is an external IdP setup and users directly assume roles
    # the additionalData.MFAUsed attribute will be set to "no"
    #  AND the userIdentity.sessionContext.mfaAuthenticated attribute will be "false"
    #
    # This will create a lack of visibility into the condition where
    #  users are allowed to directly AssumeRole outside of the IdP and without MFA
    #
    # To date we have not identified data inside the log events that clearly
    #  delinates AssumeRole backed by an external IdP vs not backed by external IdP
    if ROLES_VIA_EXTERNAL_IDP and user_identity_type == "AssumedRole":
        return False

    # If using AWS SSOv2 or other SAML provider return False
    if (
        "AWSReservedSSO" in event.udm("user_arn", default=" ")
        or event.udm("saml_provider_arn") is not None
    ):
        return False

    # If Account is less than 3 days old do not alert
    # This functionality is not enabled by default, in order to start logging new user creations
    # Enable indicator_creation_rules/new_account_logging to start logging new users
    new_user_string = (
        event.udm("actor_user", default="<MISSING_USER_NAME>")
        + "-"
        + event.udm("user_principal_id", default="<MISSING_ID>")
    )
    is_new_user = check_account_age(new_user_string)
    if isinstance(is_new_user, str):
        logging.debug("check_account_age is a mocked string for unit testing")
        if is_new_user == "False":
            is_new_user = False
        if is_new_user == "True":
            is_new_user = True
    if is_new_user:
        return False

    is_new_account = check_account_age(event.udm("recipient_account_id"))
    if isinstance(is_new_account, str):
        logging.debug("check_account_age is a mocked string for unit testing")
        if is_new_account == "False":
            is_new_account = False
        if is_new_account == "True":
            is_new_account = True
    if is_new_account:
        return False

    if event.udm("login_status") == "Success":
        # This logic is inverted because at times the second condition is None.
        # It is not recommended to remove this 'double negative"
        if event.udm("mfa_used") != "Yes" and event.udm("mfa_authenticated") != "true":
            return True
    return False


def title(event):
    if event.udm("user_type") == "Root":
        user_string = "the root user"
    else:
        user = event.udm("actor_user") or event.udm("session_user_name")
        type_ = event.udm("session_user_type", default="user").lower()
        user_string = f"{type_} {user}"
    account_id = event.udm("recipient_account_id")
    account_name = lookup_aws_account_name(account_id)
    if account_id == account_name:
        account_string = f"unnamed account ({account_id})"
    else:
        account_string = f"{account_name} account ({account_id})"

    return f"AWS login detected without MFA for [{user_string}] in [{account_string}]"


def alert_context(event):
    return aws_rule_context(event)
