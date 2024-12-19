def policy(resource):
    assume_role_policy = resource.get("AssumeRolePolicyDocument", {}).get("Statement", [])
    is_valid = False

    for statement in assume_role_policy:
        if (
            statement.get("Effect") != "Allow"
            or "sts:AssumeRoleWithWebIdentity" not in statement.get("Action", [])
        ):
            continue

        principal = statement.get("Principal", {}).get("Federated")
        if not principal or principal == "*":
            return False
        if "oidc-provider/token.actions.githubusercontent.com" not in principal:
            continue

        # Validate the conditions only if the Principal is valid for GitHub Actions
        conditions = statement.get("Condition", {})
        audience = conditions.get("StringEquals", {}).get(
            "token.actions.githubusercontent.com:aud"
        )
        subject = (
            conditions.get("StringLike", {}).get("token.actions.githubusercontent.com:sub", "")
            or conditions.get("StringEquals", {}).get("token.actions.githubusercontent.com:sub", "")
        )

        if (
            audience != "sts.amazonaws.com"
            or not subject.startswith("repo:")
            or ("*" in subject and not subject.startswith("repo:org/repo:*"))
        ):
            return False

        is_valid = True  # Mark as valid if all checks pass

    return is_valid
