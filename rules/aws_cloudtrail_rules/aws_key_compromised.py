from panther_aws_helpers import aws_rule_context

EXPOSED_CRED_POLICIES = {
    "AWSExposedCredentialPolicy_DO_NOT_REMOVE",
    "AWSCompromisedKeyQuarantine",
    "AWSCompromisedKeyQuarantineV2",
    "AWSCompromisedKeyQuarantineV3",
}


def rule(event):
    if event.get("eventName") != "PutUserPolicy":
        return False

    request_params = event.get("requestParameters", {})
    if request_params.get("policyName") not in EXPOSED_CRED_POLICIES:
        return False
    return True


def title(event):
    user_name = event.deep_get("userIdentity", "userName")
    access_key_id = event.deep_get("userIdentity", "accessKeyId")
    return (
        f"[{user_name}]'s AWS IAM Access Key ID [{access_key_id}]"
        f" was exposed and quarantined by AWS"
    )


def alert_context(event):
    return aws_rule_context(event)
