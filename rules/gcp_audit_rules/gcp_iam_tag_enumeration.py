from panther_gcp_helpers import gcp_alert_context


def rule(event):
    enum_iam_tags = [
        "GetIamPolicy",
        "TagKeys.ListTagKeys",
        "TagKeys.ListTagValues",
        "TagBindings.ListEffectiveTags",
    ]

    method_name = event.deep_get("protoPayload", "methodName", default="")
    return any(tag in method_name for tag in enum_iam_tags)


def title(event):
    principal = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>"
    )
    method = event.deep_get("protoPayload", "methodName", default="<UNKNOWN>")
    return f"GCP IAM and Tag Enumeration by {principal} - {method}"


def alert_context(event):
    return gcp_alert_context(event)
