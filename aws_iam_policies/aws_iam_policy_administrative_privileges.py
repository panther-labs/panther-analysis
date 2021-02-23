import json


# When a single item is loaded from json, it is loaded as a single item
# When a list of items is loaded from json, it is loaded as a list of that item
# When we want to iterate over something that could be a single item or a list
# of items we can use listify and just continue as if it's always a list
def listify(maybe_list):
    return [maybe_list] if not isinstance(maybe_list, list) else maybe_list


def policy(resource):
    iam_policy = json.loads(resource["PolicyDocument"])
    statements = listify(iam_policy["Statement"])
    for state in statements:
        actions = listify(state.get("Action", []))
        resources = listify(state.get("Resource", []))

        if state["Effect"] == "Allow" and "*" in actions and "*" in resources:
            return False
    return True
