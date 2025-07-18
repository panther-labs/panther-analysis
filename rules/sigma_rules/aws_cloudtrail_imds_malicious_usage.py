import re


def rule(event):
    if all(
        [
            re.match(r".+:assumed-role/aws:.+", event.deep_get("userIdentity", "arn", default="")),
            not any(
                [
                    event.deep_get("eventSource", default="") == "ssm.amazonaws.com",
                    event.deep_get("eventName", default="") == "RegisterManagedInstance",
                    event.deep_get("sourceIPAddress", default="") == "AWS Internal",
                ]
            ),
        ]
    ):
        return True
    return False
