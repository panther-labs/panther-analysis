from panther_aws_helpers import aws_rule_context

EXPOSED_CRED_POLICY = "AWSExposedCredentialPolicy_DO_NOT_REMOVE"


def rule(event):
    request_params = event.get("requestParameters", {})
    if request_params:
        return (
            event.get("eventName") == "PutUserPolicy"
            and request_params.get("policyName") == EXPOSED_CRED_POLICY
        )
    return False


def dedup(event):
    return event.deep_get("additionalEventData", "UserName")


def title(event):
    return (
        f"{dedup(event)}'s access key ID [{event.deep_get('userIdentity', 'accessKeyId')}]"
        f" was uploaded to a public GitHub repo"
    )


def alert_context(event):
    return aws_rule_context(event)
