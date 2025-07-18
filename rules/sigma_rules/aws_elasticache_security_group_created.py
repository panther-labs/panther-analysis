def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "elasticache.amazonaws.com",
            event.deep_get("eventName", default="") == "CreateCacheSecurityGroup",
        ]
    ):
        return True
    return False
