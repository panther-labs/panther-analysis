import json

REQUIRED_CONDITIONS = {
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
}


def policy(resource):
    policy_document = resource.get("Policy")
    if not policy_document:
        return True  # Pass if there is no policy document

    policy_statements = json.loads(policy_document).get("Statement", [])
    for statement in policy_statements:
        # Check if the statement allows access and includes a service principal
        principal = statement.get("Principal", {})
        if "Service" in principal and statement.get("Effect") == "Allow":
            conditions = statement.get("Condition", {})
            # Flatten nested condition keys (e.g., inside "StringEquals")
            flat_condition_keys = set()
            for condition in conditions.values():
                if isinstance(condition, dict):
                    flat_condition_keys.update(condition.keys())
            # Check if any required condition key is present
            if not REQUIRED_CONDITIONS.intersection(flat_condition_keys):
                return False

    return True
