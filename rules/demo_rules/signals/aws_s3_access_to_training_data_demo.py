def rule(event):
    return (
        event.get("bucket") == "jn-model-training-data-5233"
        and event.get("operation") == "REST.GET.OBJECT"
        and not event.get("errorcode")
    )


def alert_context(event):
    return {
        "target": {
            "bucket": event.get("bucket", ""),
            "key": event.get("key", ""),
        },
        "actor": event.get("requester", ""),
        "timestamp": event.get("p_event_time", ""),
        "parameters": {
            "user_agent": event.get("useragent", ""),
            "request_id": event.get("requestid", ""),
        },
        "action": event.get("operation", ""),
    }

def runbook(event):
    return f"""
    Investigate S3 access to training data bucket by reviewing: 1) The requester identity ({event.get("requester")}), 2) Their access patterns and volume from CloudTrail, 3) The specific objects accessed ({event.get("key")}), and 4) The source IP and user agent ({event.get("remoteip")}, {event.get("userAgent")}). If access is unauthorized, rotate any compromised credentials and review all data accessed by this principal.
    """
