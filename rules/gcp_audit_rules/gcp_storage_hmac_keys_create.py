def rule(event):
    auth_info = event.deep_walk("protoPayload", "authorizationInfo", default=[])
    auth_info = auth_info if isinstance(auth_info, list) else [auth_info]

    for auth in auth_info:
        if auth.get("granted", False) and auth.get("permission", "") == "storage.hmacKeys.create":
            return True
    return False
