import json

from policyuniverse.expander_minimizer import expand_policy
from policyuniverse.policy import Policy

# White listed policies (e.g. the approved admin policies) can be specified here, or as an
# exception to this policy.

ADMIN_ACTIONS = {
    "Permissions",
}


def policy(resource):
    iam_policy = Policy(expand_policy(json.loads(resource["PolicyDocument"])))
    action_summary = iam_policy.action_summary()

    # Sometimes AWS Service Linked Roles+Policies violate the
    # expectation as expressed in policyuniverse.
    # service-linked roles have a path of /aws-service-role/
    #   service-linked roles and their policies are not editable
    # service-role is editable, and so not included
    if resource.get("Path", "") == "/aws-service-role/":
        return True

    # Check if the policy grants any administrative privileges
    return not any(
        ADMIN_ACTIONS.intersection(action_summary[service]) for service in action_summary
    )
