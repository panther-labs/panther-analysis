def policy(resource):
    assume_role_policy = resource.get("AssumeRolePolicyDocument", {}).get("Statement", [])
    
    # Iterate through each statement in the trust policy
    for statement in assume_role_policy:
        # Check if the statement allows sts:AssumeRoleWithWebIdentity
        if statement.get("Effect") == "Allow" and "sts:AssumeRoleWithWebIdentity" in statement.get("Action", []):
            # Validate the Principal
            principal = statement.get("Principal", {}).get("Federated")
            if not principal:
                return False  # Invalid Principal
            if principal == "*":
                return False  # Wildcard in Principal is insecure
            if "oidc-provider/token.actions.githubusercontent.com" not in principal:
                continue  # Skip non-GitHub-related Principals
            
            # Validate the conditions only if the Principal is valid for GitHub Actions
            conditions = statement.get("Condition", {})
            
            # Check if the aud is correctly set
            audience = conditions.get("StringEquals", {}).get("token.actions.githubusercontent.com:aud")
            if audience != "sts.amazonaws.com":
                return False
            
            # Check if the sub is properly restricted
            subject = conditions.get("StringLike", {}).get("token.actions.githubusercontent.com:sub", "") or \
                      conditions.get("StringEquals", {}).get("token.actions.githubusercontent.com:sub", "")
            
            if not subject.startswith("repo:"):
                return False  # Ensure sub references a repository
            
            if "*" in subject and not subject.startswith("repo:org/repo:*"):
                return False  # Disallow overly permissive wildcards
            
            return True  # Valid GitHub Actions config
    
    return False  # No valid statements found
