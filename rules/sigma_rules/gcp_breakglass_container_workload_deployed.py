import json


def rule(event):
    if all(
        [
            event.deep_get("protoPayload", "resource", "type", default="") == "k8s_cluster",
            event.deep_get("protoPayload", "logName", default="")
            in ["cloudaudit.googleapis.com/activity", "cloudaudit.googleapis.com%2Factivity"],
            event.deep_get("protoPayload", "methodName", default="")
            == "io.k8s.core.v1.pods.create",
            "image-policy.k8s.io/break-glass" in json.dumps(event.to_dict()),
        ]
    ):
        return True
    return False
