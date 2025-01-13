import json


def policy(resource):
    json_policy = json.loads(resource.get("Policy", {}).get("Policy"))
    if any(
        (statement["Principal"] == "*" or statement["Principal"].get("AWS") == "*")
        and statement["Effect"] == "Allow"
        and statement.get("Condition", {}) == {}
        for statement in json_policy.get("Statement")
    ):
        return False
    return True
