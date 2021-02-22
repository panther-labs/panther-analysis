import json

from policyuniverse.action_categories import categories_for_actions
from policyuniverse.expander_minimizer import expand_policy
from policyuniverse.policy import Policy

# White listed policies (e.g. the approved network admin policy) can be specified here, or as an
# exception to this policy.

ADMIN_ACTIONS = {
    "Tagging",
    "Write",
}
NETWORK_RESOURCES = {
    "vpc",
    "securitygroup",
    "networkacl",
    "routetable",
}


def policy(resource):
    iam_policy = Policy(expand_policy(json.loads(resource["PolicyDocument"])))
    action_summary = iam_policy.action_summary()

    #
    # These first two checks can technically be skipped and this policy will still return correct
    # results, but they prevent the more computationally expensive check the majority of the time.
    #

    # Check if the policy applies to EC2 resources
    if "ec2" not in action_summary:
        return True

    # Check if the policy grants administrative privileges
    if not ADMIN_ACTIONS.intersection(action_summary["ec2"]):
        return True

    # Get the EC2 actions pertaining specifically to network resources
    network_actions = set()
    for statement in iam_policy.statements:
        # Only check statements granting access
        if statement.effect != "Allow":
            continue
        # Only check actions that are granted on network resources
        for action in statement.actions:
            if any(resource in action for resource in NETWORK_RESOURCES):
                network_actions.add(action)

    # For all actions that have been granted on network resources, ensure none grant admin access
    network_actions_summary = categories_for_actions(network_actions)
    return not any(action in ADMIN_ACTIONS for action in network_actions_summary["ec2"])
