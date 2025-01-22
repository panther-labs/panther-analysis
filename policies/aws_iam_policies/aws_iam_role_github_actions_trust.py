from panther_base_helpers import deep_get


def policy(resource):
    assume_role_policy = deep_get(resource, "AssumeRolePolicyDocument", "Statement", default=[])
    is_valid = False

    for statement in assume_role_policy:
        if statement.get(
            "Effect"
        ) != "Allow" or "sts:AssumeRoleWithWebIdentity" not in statement.get("Action", []):
            continue

        principal = deep_get(statement, "Principal", "Federated")
        if not principal or principal == "*":
            return False
        if "oidc-provider/token.actions.githubusercontent.com" not in principal:
            continue

        # Validate the conditions only if the Principal is valid for GitHub Actions
        conditions = statement.get("Condition", {})
        audience = deep_get(conditions, "StringEquals", "token.actions.githubusercontent.com:aud")
        subject = deep_get(
            conditions, "StringLike", "token.actions.githubusercontent.com:sub", default=""
        ) or deep_get(
            conditions, "StringEquals", "token.actions.githubusercontent.com:sub", default=""
        )

        if (
            audience != "sts.amazonaws.com"
            or not subject.startswith("repo:")
            or ("*" in subject and not subject.startswith("repo:org/repo:*"))
        ):
            return False

        is_valid = True  # Mark as valid if all checks pass

    return is_valid
