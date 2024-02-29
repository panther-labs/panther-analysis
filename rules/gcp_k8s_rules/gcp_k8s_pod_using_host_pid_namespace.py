from panther_base_helpers import deep_get

METHODS_TO_CHECK = [
    "io.k8s.core.v1.pods.create",
    "io.k8s.core.v1.pods.update",
    "io.k8s.core.v1.pods.patch",
]


def rule(event):
    method = deep_get(event, "protoPayload", "methodName")
    request_host_pid = deep_get(event, "protoPayload", "request", "spec", "hostPID")
    response_host_pid = deep_get(event, "protoPayload", "responce", "spec", "hostPID")
    if (request_host_pid is True or response_host_pid is True) and method in METHODS_TO_CHECK:
        return True
    return False
