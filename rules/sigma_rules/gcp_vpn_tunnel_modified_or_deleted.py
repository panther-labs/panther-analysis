def rule(event):
    if event.deep_get("protoPayload", "methodName", default="") in [
        "compute.vpnTunnels.insert",
        "compute.vpnTunnels.delete",
    ]:
        return True
    return False
