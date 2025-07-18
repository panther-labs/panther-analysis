import re


def rule(event):
    if any(
        [
            re.match(
                r"^io.k8s.core.v.*.secrets.create$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.core.v.*.secrets.update$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.core.v.*.secrets.patch$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.core.v.*.secrets.delete$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
        ]
    ):
        return True
    return False
