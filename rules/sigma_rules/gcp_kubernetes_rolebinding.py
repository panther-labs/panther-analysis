import re


def rule(event):
    if any(
        [
            re.match(
                r"^io.k8s.authorization.rbac.v.*.clusterrolebindings.create$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.rolebindings.create$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.clusterrolebindings.patch$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.rolebindings.patch$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.clusterrolebindings.update$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.rolebindings.update$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.clusterrolebindings.delete$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.authorization.rbac.v.*.rolebindings.delete$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
        ]
    ):
        return True
    return False
