from panther_base_helpers import deep_get

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
    return deep_get(event, "userIdentity", "userName")


def title(event):
    message = "{username}'s access key ID [{key}] was uploaded to a public GitHub repo"
    return message.format(username=dedup(event), key=deep_get(event, "userIdentity", "accessKeyId"))
