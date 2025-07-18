import re


def rule(event):
    if any(
        [
            re.match(
                r"^v.*.Compute.Firewalls.Delete$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.Firewalls.Patch$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.Firewalls.Update$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.Firewalls.Insert$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
        ]
    ):
        return True
    return False
