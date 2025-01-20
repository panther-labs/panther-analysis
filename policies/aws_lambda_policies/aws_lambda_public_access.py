import json

from panther_base_helpers import deep_get


def policy(resource):
    json_policy = json.loads(deep_get(resource, "Policy", "Policy"))
    if any(
        (statement.get("Principal") == "*" or deep_get(statement, "Principal", "AWS") == "*")
        and statement.get("Effect") == "Allow"
        and statement.get("Condition", {}) == {}
        for statement in json_policy.get("Statement")
    ):
        return False
    return True
