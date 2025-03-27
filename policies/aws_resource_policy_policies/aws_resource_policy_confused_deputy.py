import json

REQUIRED_CONDITIONS = {
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
}

# Service-specific condition keys that can provide additional protection
SERVICE_SPECIFIC_CONDITIONS = {
    "lambda:FunctionUrlAuthType",  # Lambda function URL auth type
    # TODO(Panther): Add service-specific conditions for additional resource types once supported:
    # "secretsmanager:ResourceTag",    # Secrets Manager resource tags
    # "sqs:*",                         # SQS queue operations
    # "sns:*",                         # SNS topic operations
    # "execute-api:*",                 # API Gateway operations
    # "ecr:*",                         # ECR repository operations
    # "elasticfilesystem:*",           # EFS file system operations
    # "backup:*",                      # Backup vault operations
    # "codeartifact:*",               # CodeArtifact repository operations
    # "events:*",                      # EventBridge event bus operations
    # "glacier:*",                     # Glacier vault operations
}


def is_service_principal(principal):
    """Check if the principal is a service principal or allows unrestricted access."""
    if isinstance(principal, str):
        return principal == "*"

    if not isinstance(principal, dict):
        return False

    # Check for direct service principal
    if principal.get("Service") is not None:
        return True

    # Check for wildcard access
    aws_principal = principal.get("AWS")
    if aws_principal == "*":
        return True
    if isinstance(aws_principal, list) and "*" in aws_principal:
        return True

    return False


def check_condition_keys(conditions, required_keys):
    """Check if any of the required keys exist in the condition values."""
    if not isinstance(conditions, dict):
        return False

    for condition_values in conditions.values():
        if isinstance(condition_values, dict):
            if any(key in condition_values for key in required_keys):
                return True
    return False


def has_service_specific_condition(conditions):
    """Check if any service-specific condition keys are present."""
    if not isinstance(conditions, dict):
        return False

    for condition_values in conditions.values():
        if isinstance(condition_values, dict):
            for key in condition_values:
                if any(key.startswith(prefix) for prefix in SERVICE_SPECIFIC_CONDITIONS):
                    return True
    return False


def check_statement_conditions(statement):
    """Check if a policy statement has appropriate confused deputy protections."""
    if statement.get("Effect") != "Allow":
        return True

    principal = statement.get("Principal", {})
    if not is_service_principal(principal):
        return True

    conditions = statement.get("Condition", {})

    # Check for aws:PrincipalIsAWSService condition
    service_conditions = conditions.get("Bool", {})
    if service_conditions.get("aws:PrincipalIsAWSService") == "true":
        # If explicitly checking for service principal, must have required or
        # service-specific conditions
        return has_service_specific_condition(conditions) or check_condition_keys(
            conditions, REQUIRED_CONDITIONS
        )

    # For all other cases with service principals, check conditions
    flat_condition_keys = set()
    for condition_values in conditions.values():
        if isinstance(condition_values, dict):
            flat_condition_keys.update(condition_values)

    return bool(REQUIRED_CONDITIONS.intersection(flat_condition_keys)) or any(
        any(key.startswith(prefix) for prefix in SERVICE_SPECIFIC_CONDITIONS)
        for key in flat_condition_keys
    )


def policy(resource):
    resource_policy = resource.get("Policy") or resource.get("ResourcePolicy")
    if resource_policy is None:
        return True  # Pass if there is no resource policy

    try:
        policy_doc = json.loads(resource_policy)
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]  # Handle single statement case
    except json.JSONDecodeError:
        return True  # Pass if policy is not valid JSON

    return all(check_statement_conditions(statement) for statement in statements)
