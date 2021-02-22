import json
from policyuniverse.expander_minimizer import minimize_statement_actions

BAD_ACTIONS = {
    "*",
    "s3:*",
}


def policy(resource):
    if resource["Policy"] is None:
        return True

    iam_policy = json.loads(resource["Policy"])
    for statement in iam_policy["Statement"]:
        # Only check statements granting access
        if statement["Effect"] != "Allow":
            continue

        minimized_actions = minimize_statement_actions(statement)
        if BAD_ACTIONS.intersection(minimized_actions):
            return False

    return True
