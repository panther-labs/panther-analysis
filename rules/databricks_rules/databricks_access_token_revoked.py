from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    return event.get("actionName") == "revokeDbToken"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    token_id = event.deep_get("requestParams", "tokenId", default="Unknown Token")
    return f"Access token revoked: {token_id} by {actor}"


def dedup(event):
    token_id = event.deep_get("requestParams", "tokenId", default="unknown")
    return f"token_revoked_{token_id}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "token_id": event.deep_get("requestParams", "tokenId"),
        },
    )
