def mongodb_alert_context(event) -> dict:
    return {
        "username": event.get("username", "<USER_NOT_FOUND>"),
        "target_username": event.get("targetUsername", "<USER_NOT_FOUND>"),
        "org_id": event.get("orgId", "<ORG_NOT_FOUND>"),
        "remote_address": event.get("remoteAddress", "<REMOTE_ADDRESS_NOT_FOUND>"),
    }
