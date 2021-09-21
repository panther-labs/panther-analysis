import json
from panther_oss_helpers import listify

def policy(resource):
    iam_policy = json.loads(resource["PolicyDocument"])
    statements = listify(iam_policy["Statement"])
    for state in statements:
        actions = listify(state.get("Action", []))
        resources = listify(state.get("Resource", []))

        if state["Effect"] == "Allow" and "*" in actions and "*" in resources:
            return False
    return True
