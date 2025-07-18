def rule(event):
    if all(
        [
            event.deep_get("protoPayload", "methodName", default="").startswith(
                "admissionregistration.k8s.io.v"
            ),
            any(
                [
                    ".mutatingwebhookconfigurations."
                    in event.deep_get("protoPayload", "methodName", default=""),
                    ".validatingwebhookconfigurations."
                    in event.deep_get("protoPayload", "methodName", default=""),
                ]
            ),
            any(
                [
                    event.deep_get("protoPayload", "methodName", default="").endswith("create"),
                    event.deep_get("protoPayload", "methodName", default="").endswith("patch"),
                    event.deep_get("protoPayload", "methodName", default="").endswith("replace"),
                ]
            ),
        ]
    ):
        return True
    return False
