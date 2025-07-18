def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "rds.amazonaws.com",
            event.deep_get("eventName", default="")
            in [
                "AuthorizeDBSecurityGroupIngress",
                "CreateDBSecurityGroup",
                "DeleteDBSecurityGroup",
                "RevokeDBSecurityGroupIngress",
            ],
        ]
    ):
        return True
    return False
