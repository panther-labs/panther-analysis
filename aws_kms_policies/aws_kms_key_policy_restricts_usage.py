import json
from policyuniverse.policy import Policy

BAD_PRINCIPALS = {
    "*",
}

BAD_ACTIONS = {
    "*",
    "kms:*",
}


def policy(resource):
    if resource["Policy"] is None:
        return True

    iam_policy = Policy(json.loads(resource["Policy"]))

    for statement in iam_policy.statements:
        # Only apply to allow effects
        if statement.effect != "Allow":
            continue

        # Don't apply where there are strong conditions
        if statement.condition_entries:
            continue

        if BAD_PRINCIPALS.intersection(statement.principals) and BAD_ACTIONS.intersection(
            statement.actions
        ):
            return False
        if statement.uses_not_principal():
            return False

    return True
