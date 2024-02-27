from panther_base_helpers import deep_walk


def rule(event):
    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False
    for auth in authorization_info:
        if (
            auth.get("permission") == "io.k8s.apps.v1.daemonsets.create"
            and auth.get("granted") is True
        ):
            return True
    return False
