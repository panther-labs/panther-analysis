import json
from policyuniverse.policy import Policy


def policy(resource):
    if resource['Policy'] is None:
        return True

    iam_policy = Policy(json.loads(resource['Policy']))

    for statement in iam_policy.statements:
        if statement.effect == 'Allow' and statement.uses_not_principal():
            return False

    return True
