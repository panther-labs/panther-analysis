import json
from policyuniverse.policy import Policy


def policy(resource):
    if resource['Policy'] is None:
        return False

    iam_policy = Policy(json.loads(resource['Policy']))

    for statement in iam_policy.statements:
        if statement.effect != 'Allow':
            continue
        if ('Condition' not in statement.statement or
                'Bool' not in statement.statement['Condition'] or
                'aws:SecureTransport'
                not in statement.statement['Condition']['Bool'] or
                statement.statement['Condition']['Bool']['aws:SecureTransport']
                != 'true'):
            return False

    return True
