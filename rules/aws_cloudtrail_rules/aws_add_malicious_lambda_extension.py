from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    # First check if this is a Lambda configuration update with layers
    if (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") == "UpdateFunctionConfiguration20150331v2"
        and event.deep_get("responseElements", "layers")
    ):
        # Alert only when identity type is IAMUser (direct credentials, not role)
        # This indicates someone bypassed normal CI/CD automation
        identity_type = event.deep_get("userIdentity", "type", default="")
        return identity_type == "IAMUser"

    return False


def title(event):
    identity_type = event.deep_get("userIdentity", "type", default="")
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )

    if identity_type == "IAMUser":
        user_name = event.deep_get("userIdentity", "userName", default="UNKNOWN_USER")
        return (
            f"[AWS.Lambda.UpdateFunctionConfiguration] IAM User [{user_name}] "
            f"updated Lambda function configuration with layers for [{lambda_name}]"
        )

    # Fallback for other identity types (shouldn't trigger, but just in case)
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"updated Lambda function configuration with layers for [{lambda_name}]"
    )


def severity(event):  # pylint: disable=unused-argument
    # IAM User modifying Lambda layers is high severity
    # This is unusual and bypasses normal CI/CD guardrails
    return "HIGH"


def alert_context(event):
    context = aws_rule_context(event)

    # Add IAM user specific context
    context["iam_user"] = event.deep_get("userIdentity", "userName")
    context["access_key_id"] = event.deep_get("userIdentity", "accessKeyId")
    context["user_arn"] = event.deep_get("userIdentity", "arn")
    context["identity_type"] = event.deep_get("userIdentity", "type")

    # Check MFA status (IAM users should use MFA)
    context["mfa_authenticated"] = event.deep_get(
        "userIdentity", "sessionContext", "attributes", "mfaAuthenticated"
    )

    # Layer details
    layers = event.deep_get("responseElements", "layers", default=[])
    context["layers"] = layers
    context["layer_count"] = len(layers)
    context["layer_arns"] = [layer.get("arn") for layer in layers]

    return context
