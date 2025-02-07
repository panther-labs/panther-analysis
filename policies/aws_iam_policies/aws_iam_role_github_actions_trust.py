import json

from panther_base_helpers import deep_get


ALLOWED_ORG_REPO_PAIRS = ["org/repo", "allowed-org-example/allowed-repo-example"]


def policy(resource):
    # check if resource.AssumRolePolicyDocument is a string, and if so convert to json
    if isinstance(resource.get("AssumeRolePolicyDocument"), str):
        policy_document = json.loads(resource.get("AssumeRolePolicyDocument", {}))
    else:
        policy_document = resource.get("AssumeRolePolicyDocument", {})
    assume_role_policy = policy_document.get("Statement", [])

    for statement in assume_role_policy:
        # only check for Allow sts:AssumeRoleWithWebIdentity
        if (
            statement.get("Effect") != "Allow"
            or statement.get("Action") != "sts:AssumeRoleWithWebIdentity"
        ):
            continue

        principal = deep_get(statement, "Principal", "Federated")
        audience = deep_get(
            statement, "Condition", "StringEquals", "token.actions.githubusercontent.com:aud"
        )
        subject = deep_get(
            statement,
            "Condition",
            "StringLike",
            "token.actions.githubusercontent.com:sub",
            default="",
        ) or deep_get(
            statement,
            "Condition",
            "StringEquals",
            "token.actions.githubusercontent.com:sub",
            default="",
        )

        if subject.startswith("repo:"):
            # repo subjects must have github as the principal and sts.amazonaws.com as the audience
            if any(
                [
                    "oidc-provider/token.actions.githubusercontent.com" not in principal,
                    audience != "sts.amazonaws.com",
                    (
                        "*" in subject
                        and not any(
                            subject.startswith(f"repo:{org_repo}:*")
                            for org_repo in ALLOWED_ORG_REPO_PAIRS
                        )
                    ),
                ]
            ):
                return False
        else:
            # non-repo subjects must not have github as the principal
            if "oidc-provider/token.actions.githubusercontent.com" in principal:
                return False

    return True
