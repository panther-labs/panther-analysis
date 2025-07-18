import re


def rule(event):
    if any(
        [
            re.match(
                r"^io.k8s.api.batch.v.*.Job$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^io.k8s.api.batch.v.*.CronJob$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
        ]
    ):
        return True
    return False
