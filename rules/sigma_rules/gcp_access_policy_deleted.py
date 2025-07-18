def rule(event):
    if all(
        [
            event.deep_get("protoPayload", "authorizationInfo", "permission", default="")
            in [
                "accesscontextmanager.accessPolicies.delete",
                "accesscontextmanager.accessPolicies.accessLevels.delete",
                "accesscontextmanager.accessPolicies.accessZones.delete",
                "accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete",
            ],
            event.deep_get("protoPayload", "authorizationInfo", "granted", default="") == "true",
            event.deep_get("protoPayload", "serviceName", default="")
            == "accesscontextmanager.googleapis.com",
        ]
    ):
        return True
    return False
