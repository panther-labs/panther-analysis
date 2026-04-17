import json

REQUIRED_CONDITIONS = {
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
}


def policy(resource):
    bucket_policy = resource.get("Policy")
    if bucket_policy is None:
        return True  # Pass if there is no bucket policy

    policy_statements = json.loads(bucket_policy).get("Statement", [])
    for statement in policy_statements:
        # Check if the statement includes a service principal and allows access
        principal = statement.get("Principal", {})
        if "Service" in principal and statement["Effect"] == "Allow":
            conditions = statement.get("Condition", {})
            # Flatten nested condition keys (e.g., inside "StringEquals")
            flat_condition_keys = set()
            for condition in conditions.values():
                if isinstance(condition, dict):
                    flat_condition_keys.update(condition.keys())
            # Check if any required condition key is present
            if not {str.casefold(x) for x in REQUIRED_CONDITIONS} & {
                str.casefold(x) for x in flat_condition_keys
            }:
                return False
    return True
