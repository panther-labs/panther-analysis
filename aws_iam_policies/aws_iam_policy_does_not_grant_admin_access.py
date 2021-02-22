import json
from policyuniverse.policy import Policy
from policyuniverse.expander_minimizer import expand_policy

# White listed policies (e.g. the approved admin policies) can be specified here, or as an
# exception to this policy.

ADMIN_ACTIONS = {
    "Permissions",
}


def policy(resource):
    iam_policy = Policy(expand_policy(json.loads(resource["PolicyDocument"])))
    action_summary = iam_policy.action_summary()

    # Check if the policy grants any administrative privileges
    return not any(
        ADMIN_ACTIONS.intersection(action_summary[service]) for service in action_summary
    )
