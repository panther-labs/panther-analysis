def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "route53.amazonaws.com",
            event.deep_get("eventName", default="") == "TransferDomainToAnotherAwsAccount",
        ]
    ):
        return True
    return False
