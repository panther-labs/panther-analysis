from panther_base_helpers import deep_walk


def rule(event):
    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    for auth in authorization_info:
        if (
            auth.get("permission") == "cloudfunctions.functions.create"
            and auth.get("granted") is True
        ):
            return True
    return False
