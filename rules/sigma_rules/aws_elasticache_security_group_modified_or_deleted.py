def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "elasticache.amazonaws.com",
            event.deep_get("eventName", default="")
            in [
                "DeleteCacheSecurityGroup",
                "AuthorizeCacheSecurityGroupIngress",
                "RevokeCacheSecurityGroupIngress",
                "AuthorizeCacheSecurityGroupEgress",
                "RevokeCacheSecurityGroupEgress",
            ],
        ]
    ):
        return True
    return False
