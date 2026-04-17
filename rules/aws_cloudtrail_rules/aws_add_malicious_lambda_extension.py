from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") == "UpdateFunctionConfiguration20150331v2"
        and event.deep_get("responseElements", "layers")
    ):
        return False

    identity_type = event.deep_get("userIdentity", "type", default="")
    if identity_type in ("IAMUser", "FederatedUser"):
        return True
    if identity_type == "AssumedRole":
        role_name = event.deep_get(
            "userIdentity", "sessionContext", "sessionIssuer", "userName", default=""
        )
        return role_name.startswith("AWSReservedSSO_")
    return False


def title(event):
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"updated Lambda function configuration with layers for [{lambda_name}]"
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["identity_type"] = event.deep_get("userIdentity", "type")
    context["user_arn"] = event.deep_get("userIdentity", "arn")

    layers = event.deep_get("responseElements", "layers", default=[])
    context["layer_arns"] = [layer.get("arn") for layer in layers]

    return context
