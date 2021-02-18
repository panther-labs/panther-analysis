import json
from policyuniverse.policy import Policy
from panther_base_helpers import deep_get


def policy(resource):
    if resource['Policy'] is None:
        return False

    iam_policy = Policy(json.loads(resource['Policy']))

    for statement in iam_policy.statements:
        if statement.effect != 'Allow':
            continue
        if not deep_get(statement.statement, 'Condition', 'Bool',
                        'aws:SecureTransport'):
            return False

    return True
